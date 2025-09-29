def call(Map args = [:]) {
    def services = args.get('services', [])
    if (services.isEmpty()) {
        error "No services provided for Snyk scan"
    }

    def foundHigh = false

    withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
        sh "snyk auth \$SNYK_TOKEN"

        for (svc in services) {
            echo "==============================="
            echo "Scanning container for: ${svc}"
            echo "==============================="

            // שלב 1 - בודקים קריטיות
            def criticalExitCode = sh(
                script: "snyk container test ${svc} --severity-threshold=critical",
                returnStatus: true
            )

            if (criticalExitCode != 0) {
                echo "Found CRITICAL vulnerabilities in ${svc} - failing pipeline."
                error("Stopping pipeline due to critical vulnerabilities in ${svc}") // זה יגרום ל-stage להיות אדום
            }

            // שלב 2 - בודקים High
            def highExitCode = sh(
                script: "snyk container test ${svc} --severity-threshold=high",
                returnStatus: true
            )

            if (highExitCode != 0) {
                echo "Found HIGH vulnerabilities in ${svc}"
                foundHigh = true
            } else {
                echo "No critical or high vulnerabilities found for ${svc}."
            }

            // שולח Snapshot ל-Snyk UI
            sh "snyk container monitor ${svc} || true"
        }

        // אם לפחות שירות אחד עם High -> מחזיר exit 1 כדי ש-Jenkins יתפוס כ-UNSTABLE
        if (foundHigh) {
            echo "Marking stage as UNSTABLE because at least one service had HIGH vulnerabilities."
            sh "exit 1"  // מחזיר קוד יציאה ≠ 0
        } else {
            echo "All services scanned clean (no critical/high vulnerabilities)."
        }
    }
}
