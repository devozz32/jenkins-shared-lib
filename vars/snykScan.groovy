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
            echo "Scanning container for \$svc"
            snyk container test \$svc --json > \${svc}-snyk.json || true

            CRITICAL=\$(jq '[.vulnerabilities[] | select(.severity=="critical")] | length' \${svc}-snyk.json)
            HIGH=\$(jq '[.vulnerabilities[] | select(.severity=="high")] | length' \${svc}-snyk.json)
            MED=\$(jq '[.vulnerabilities[] | select(.severity=="medium")] | length' \${svc}-snyk.json)

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
