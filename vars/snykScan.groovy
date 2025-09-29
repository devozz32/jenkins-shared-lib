def call(Map args = [:]) {
    def services = args.get('services', [])
    if (services.isEmpty()) {
        error "No services provided for Snyk scan"
    }

    withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
        for (svc in services) {
            sh """
            set -e
            snyk auth \$SNYK_TOKEN

            SAFE_NAME=\$(echo ${svc} | sed 's#[/:]#_#g')
            echo "==============================="
            echo "Scanning container for: ${svc}"
            echo "==============================="

            snyk container test ${svc} --json > \${SAFE_NAME}-snyk.json || true

            if [ ! -s \${SAFE_NAME}-snyk.json ]; then
                echo "No results produced by Snyk for ${svc} - skipping"
                exit 1
            fi

            CRITICAL=\$(jq '[.vulnerabilities[]? | select(.severity=="critical")] | length' \${SAFE_NAME}-snyk.json)
            HIGH=\$(jq '[.vulnerabilities[]? | select(.severity=="high")] | length' \${SAFE_NAME}-snyk.json)
            MED=\$(jq '[.vulnerabilities[]? | select(.severity=="medium")] | length' \${SAFE_NAME}-snyk.json)

            echo "Results for ${svc}:"
            echo "  Critical: \$CRITICAL"
            echo "  High:     \$HIGH"
            echo "  Medium:   \$MED"

            snyk container monitor ${svc} || true

            if [ "\$CRITICAL" -gt 0 ]; then
                echo "Found \$CRITICAL critical vulnerabilities. Failing pipeline."
                exit 2
            elif [ "\$HIGH" -gt 0 ]; then
                echo "Found \$HIGH high vulnerabilities. Marking as UNSTABLE."
                exit 1
            fi

            echo "No significant vulnerabilities found for ${svc}."
            """
            
            // קוד היציאה מהפקודה למטה יגיד לג'נקינס אם זה אדום או צהוב
            script {
                def lastCode = sh(script: "echo \$?", returnStdout: true).trim()
                if (lastCode == "2") {
                    currentBuild.result = 'FAILURE'
                    error("Stopping pipeline due to critical vulnerabilities")
                } else if (lastCode == "1") {
                    currentBuild.result = 'UNSTABLE'
                }
            }
        }
    }
}
