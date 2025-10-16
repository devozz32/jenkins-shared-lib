def call(Map args = [:]) {
    def services = args.get('services', [])
    if (services.isEmpty()) {
        error "No services provided for Snyk scan"
    }

    def foundHigh = false
    def foundCritical = false

    withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
        sh "snyk auth \$SNYK_TOKEN"

        for (svc in services) {
            echo "==============================="
            echo "Scanning container for: ${svc}"
            echo "==============================="

            // בדיקה עבור CRITICAL (לא תכשיל את הפייפליין)
            def criticalExitCode = sh(
                script: "snyk container test ${svc} --severity-threshold=critical || true",
                returnStatus: true
            )

            if (criticalExitCode != 0) {
                echo "🚨 Found CRITICAL vulnerabilities in ${svc} (pipeline will continue)"
                foundCritical = true
            }

            // בדיקה עבור HIGH
            def highExitCode = sh(
                script: "snyk container test ${svc} --severity-threshold=high || true",
                returnStatus: true
            )

            if (highExitCode != 0) {
                echo "⚠️ Found HIGH vulnerabilities in ${svc}"
                foundHigh = true
            } else if (criticalExitCode == 0) {
                echo "✅ No critical or high vulnerabilities found for ${svc}."
            }

            // שליחת Snapshot ל־Snyk
            sh "snyk container monitor ${svc} || true"
        }

        // מסקנה כללית
        if (foundCritical || foundHigh) {
            echo "⚠️ Vulnerabilities detected — build will be marked as UNSTABLE."
            currentBuild.result = 'UNSTABLE'
        } else {
            echo "✅ All services scanned clean (no critical/high vulnerabilities)."
        }
    }
}
