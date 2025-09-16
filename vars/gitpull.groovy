def call(String repoUrl, String branchName) {
    println "git pull from:${repoUrl}, branch: ${branchName}"
    def pullCmd = ["git", "-C", ".", "pull", repoUrl, branchName]
    def pullProc = pullCmd.execute()
    pullProc.waitForProcessOutput(System.out, System.err)
    println "Done git pull"
}
