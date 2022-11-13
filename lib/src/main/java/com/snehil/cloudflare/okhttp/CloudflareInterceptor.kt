package com.snehil.cloudflare.okhttp

import android.util.Log
import com.snehil.cloudflare.okhttp.exceptions.UnsupportedChallengeException
import com.snehil.cloudflare.okhttp.uam.UAMPageAttributes
import com.snehil.cloudflare.okhttp.uam.UAMSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl

class CloudflareInterceptor(private val uamSettings: UAMSettings) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val oldRequest: Request = chain.request()
        val request = oldRequest.newBuilder()
            .headers(headers)
            .get()
            .build()

        val response = chain.proceed(request)

        Log.i(TAG, "intercept: $response")
        if (response.code == 200 || response.code == 404 || response.code == 403) return response

        Log.d(TAG, "response was not valid")
        val page = response.peekBody(Long.MAX_VALUE).string()
        return when {
            isIUAMChallenge(response, page) -> runBlocking {
                Log.i(TAG, "intercept: got IUAMChallenge")
                withContext(Dispatchers.IO) {
                    chain.proceed(
                        solveCFChallenge(
                            response,
                            page
                        )
                    )
                }
            }
            isCaptchaChallenge(response, page) -> {
                Log.e(TAG, "Unsupported challenge $page")
                throw UnsupportedChallengeException()
            }
            else -> {
                Log.i(TAG, "intercept: got normal request")
                response.newBuilder().build()
            }
        }
    }

    /**
     * Default headers.
     * These headers must be all set in order to bypass the IUAM page
     */
    private val headers = Headers.headersOf(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.42",
        "Upgrade-Insecure-Requests",
        "1",
        "Accept-Language",
        "en-US,en;q=0.5",
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    )

    /**
     * Solve the IUAM challenge by evaluating parts of javascripts inside the page.
     * This method is asynchronous and uses Rhino mozilla engine.
     *
     * @param response OkHttp response of the IUAM page
     * @param page Body content of the response
     *
     * @return OkHttp response with bypassed content
     */
    private suspend fun solveCFChallenge(
        response: Response,
        page: String
    ): Request {
        val urlTemplate = "%s://%s"
        val scheme = response.request.url.scheme
        val host = response.request.url.host

        kotlinx.coroutines.delay(uamSettings.delay)

        //By accessing "formParams" the JS is automatically resolved and the challenge completed
        val attributes = UAMPageAttributes(scheme, host, page)
        val formParams = attributes.formParams

        //Build the new url
        val urlToConnect = String.format(
            urlTemplate,
            scheme,
            host
        ) + formParams.action.first + formParams.action.second
        val httpUrl = urlToConnect.toHttpUrl().newBuilder()
            .addQueryParameter(
                formParams.action.first.substringAfter("?"),
                formParams.action.second
            )
            .addQueryParameter("jschl_vc", formParams.jschlVc)
            .addQueryParameter("pass", formParams.pass)
            .addQueryParameter("jschl_answer", formParams.jschlAnswer)
            .build()

        //Build the body with challenge answer
        val formBody = FormBody.Builder()
            .add("r", formParams.r)
            .add("jschl_vc", formParams.jschlVc)
            .add("pass", formParams.pass)
            .add("jschl_answer", formParams.jschlAnswer)
            .build()

        //Build the post request

        //This should return the real website with cf_clearance cookie
        //used to automatically skip the countdown the next times

        return Request.Builder()
            .url(httpUrl)
            .headers(headers)
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .post(formBody)
            .build()
    }


    /**
     * Check if the page is cloudflare's IUAM page
     *
     * @param response OkHttp response of the initially requested page (the one that could be IUAM)
     * @param page Body content of the response
     *
     * @return true if the page is IUAM
     */
    private fun isIUAMChallenge(response: Response, page: String) =
        response.code in 503 downTo 429
                && response.headers["Server"]!!.startsWith("cloudflare")
                && page.contains("jschl_answer")

    /**
     * Check if the page contains a Captcha challenge
     *
     * @param response OkHttp response of the initially requested page
     * @param page Body content of the response
     *
     * @return true if the page contains a Captcha challenge
     */
    private fun isCaptchaChallenge(response: Response, page: String) =
        response.code == 403
                && response.headers["Server"]!!.startsWith("cloudflare")
                && page.contains("/cdn-cgi/l/chk_captcha")

    companion object {
        private const val TAG = "CloudflareInterceptor"
    }
}
