def call() {
    def gitUrl = scm.getUserRemoteConfigs()[0].getUrl()
    return gitUrl.tokenize('/').last().replace('.git','')
}
