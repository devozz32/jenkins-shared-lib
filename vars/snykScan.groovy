def call(Map args = [:]) {
    def services = args.get('services', [])
    if (services.isEmpty()) {
        error "No services provided for Snyk scan"
    }

    withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
        sh """
        set -e
        EXIT_CODE=0
        for svc in ${services.join(' ')}; do
            SAFE_NAME=\$(echo \$svc | sed 's#[/:]#_#g')
            echo "Scanning container for \$svc"
            snyk container test \$svc --json > \${SAFE_NAME}-snyk.json || true

            CRITICAL=\$(jq '[.vulnerabilities[] | select(.severity=="critical")] | length' \${SAFE_NAME}-snyk.json)
            HIGH=\$(jq '[.vulnerabilities[] | select(.severity=="high")] | length' \${SAFE_NAME}-snyk.json)
            MED=\$(jq '[.vulnerabilities[] | select(.severity=="medium")] | length' \${SAFE_NAME}-snyk.json)

            echo "Results for \$svc:"
            if [ "\$CRITICAL" -gt 0 ] || [ "\$HIGH" -gt 0 ]; then
                echo "Remark: Found \$CRITICAL critical and \$HIGH high vulnerabilities. Failing pipeline."
                EXIT_CODE=1
            elif [ "\$MED" -gt 0 ]; then
                echo "Remark: Found \$MED medium vulnerabilities. Review recommended."
            else
                echo "Remark: No significant vulnerabilities found."
            fi
        done

        exit \$EXIT_CODE
        """
    }
}
