
def call() {
    echo "🧹 Cleaning all files from workspace..."
    sh '''
        rm -rf ./* || true
    '''
    echo "Workspace is now clean."
}
