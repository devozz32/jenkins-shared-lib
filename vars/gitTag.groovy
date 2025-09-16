def call(String repoUrl, String tagName, String message = "") {
    // Set user.name if missing
    def nameCheck = sh(returnStdout: true, script: 'git config --get user.name').trim()
    if (!nameCheck) {
        echo "user.name not set - setting to 'Jenkins CI'"
        sh 'git config --global user.name "Jenkins CI"'
    }

    // Set user.email if missing
    def emailCheck = sh(returnStdout: true, script: 'git config --get user.email').trim()
    if (!emailCheck) {
        echo "user.email not set - setting to 'jenkins@ci.local'"
        sh 'git config --global user.email "jenkins@ci.local"'
    }

    echo "Creating tag '${tagName}' on HEAD"
    if (message) {
        sh "git tag -a ${tagName} -m \"${message}\" HEAD"
    } else {
        sh "git tag ${tagName} HEAD"
    }

    echo "Pushing tag to remote ${repoUrl}"
    sh "git push ${repoUrl} ${tagName}"

    echo "Tag '${tagName}' created and pushed successfully"
}

//gitTag("https://github.com/username/repo.git", "build-${env.BUILD_NUMBER}", "Automated build ${env.BUILD_NUMBER}")
