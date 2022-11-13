package com.snehil.cloudflare.okhttp.uam

import com.snehil.cloudflare.okhttp.util.JavascriptEvaluator

/**
 * Holds the params used to perform the final POST request.
 * These params are picked by the <form> element of the IUAM page
 *
 * @param r Form name "r"
 * @param jschlVc Form name "jschl_vc"
 * @param pass Form name "pass"
 * @param jschlAnswer Form name "jschl_answer" (the answer of the challenge)
 */
data class UAMPageFormParams(
    val r: String,
    val jschlVc: String,
    val pass: String,
    val jschlAnswer: String,
    val action: Pair<String, String>
) {

    companion object {

        /**
         * Get form params from a [UAMPageAttributes]
         *
         * @return [UAMPageAttributes] built parsing the IUAM page
         */
        @JvmStatic
        fun fromUAMPage(pageAttributes: UAMPageAttributes): UAMPageFormParams {
            val page = pageAttributes.page

            //Parse every already set values
            val r = Regex("name=\"r\" value=\"([^\"]*)\"").find(page)!!.groupValues[1]
            val jschlVc =
                Regex("name=\"jschl_vc\" value=\"([^\"]*)\"|value=\"([^\"]*)\".+?name=\"jschl_vc\"").find(
                    page
                )!!.let {
                    it.groupValues[1].ifEmpty { it.groupValues[2] }
                }

            val pass = Regex("name=\"pass\" value=\"([^\"]*)\"").find(page)!!.groupValues[1]
            val action = """action="([^"]+)"""".toRegex().find(page)!!.groupValues[1]
                .split("=").let { Pair(it[0], it[1]) }

            //Solve the challenge to find the last form param
            val jschlAnswer =
                getJschlAnswerFromPage(
                    pageAttributes
                )

            return UAMPageFormParams(
                r,
                jschlVc,
                pass,
                jschlAnswer,
                action
            )
        }

        /**
         * Solves the challenge of the IUAM page
         *
         * @return The challenge solution
         */
        @JvmStatic
        private fun getJschlAnswerFromPage(pageAttributes: UAMPageAttributes): String {
            //Select the script tag content
            val scriptText = """<script .+?>([^€]+?)</script>""".toRegex()
                .find(pageAttributes.page)!!.groupValues[1]


            println(scriptText)

            //Select the important script text
            var importantScriptText =
                """setTimeout\(function\(\)\{([^€]+?toFixed\([0-9][0-9]\))""".toRegex()
                    .find(scriptText)!!.groupValues[1]

            //Replace 't' with the hostname(domain)
            importantScriptText = importantScriptText.replace(
                """t = d[^€]+?-1\);""".toRegex(), "t = \"${pageAttributes.host}\";"
            )

            //Remove 'getElementById' references
            importantScriptText = importantScriptText.replace(
                """[af] = document.+?;""".toRegex(), ""
            )

            //Add fake 'a' element
            importantScriptText = "var a = {value: 0.0};\n$importantScriptText"

            //Create a fake 'document' object to return the correct value for 'k' if exists
            val correctValue = """id="cf-dn.+?>(.+?)</div>""".toRegex()
                .find(pageAttributes.page)?.groupValues?.get(1)
            if (correctValue != null) {
                val documentObject =
                    "var document={getElementById:(i)=>{return{innerHTML:`$correctValue`}}};"
                importantScriptText = documentObject + importantScriptText
            }


            //Print the result in script
            importantScriptText += ";\na.value;"

            //Evaluate and return
            val javascriptEvaluator = JavascriptEvaluator.get()
            return javascriptEvaluator.evaluateString(importantScriptText)
        }

    }

}