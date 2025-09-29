def call(Map args = [:]) {
    def services = args.get('services', [])
    if (services.isEmpty()) {
        error "No services provided for Snyk scan"
    }

    withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
        sh """
        set -e
        snyk auth \$SNYK_TOKEN
        EXIT_CODE=0

        for svc in ${services.join(' ')}; do
            SAFE_NAME=\$(echo \$svc | sed 's#[/:]#_#g')
            echo "==============================="
            echo "Scanning container for: \$svc"
            echo "==============================="

            # שמירה של התוצאה ל-JSON (גם אם יש שגיאה ממשיכים)
            snyk container test \$svc --json > \${SAFE_NAME}-snyk.json || true

            if [ ! -s \${SAFE_NAME}-snyk.json ]; then
                echo "No results produced by Snyk for \$svc - skipping"
                EXIT_CODE=1
                continue
            fi

            # ספירת פגיעויות בצורה בטוחה (אם אין vulnerabilities נקבל 0)
            CRITICAL=\$(jq '[.vulnerabilities[]? | select(.severity=="critical")] | length' \${SAFE_NAME}-snyk.json)
            HIGH=\$(jq '[.vulnerabilities[]? | select(.severity=="high")] | length' \${SAFE_NAME}-snyk.json)
            MED=\$(jq '[.vulnerabilities[]? | select(.severity=="medium")] | length' \${SAFE_NAME}-snyk.json)

            echo "Results for \$svc:"
            echo "  Critical: \$CRITICAL"
            echo "  High:     \$HIGH"
            echo "  Medium:   \$MED"

            # שולח את התוצאה ל-Snyk UI לחשבון שלך
            snyk container monitor \$svc || true

            if [ "\$CRITICAL" -gt 0 ] || [ "\$HIGH" -gt 0 ]; then
                echo "Remark: Found \$CRITICAL critical and \$HIGH high vulnerabilities. Failing pipeline."
                EXIT_CODE=1
            elif [ "\$MED" -gt 0 ]; then
                echo "Remark: Found \$MED medium vulnerabilities. Review recommended."
            else
                echo "Remark: No significant vulnerabilities found."
            fi
            echo ""
        done

        exit \$EXIT_CODE
        """
    }
}
