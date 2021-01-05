//def ReleaseDir = "c:\inetpub\wwwroot"
pipeline {
			agent any
			stages {
				stage('Source'){
					steps{
						checkout([$class: 'GitSCM', branches: [[name: '*/main']], doGenerateSubmoduleConfigurations: false, extensions: [], submoduleCfg: [], userRemoteConfigs: [[credentialsId: '825fc4d4-4161-4170-9587-28a936f82af6', url: 'https://github.com/senthamizhs/KUM19.git']]])
					}
				}
				stage('Build') {
    					steps {
    					    bat "\"${tool 'MSBuild'}\" iphelp.sln /p:DeployOnBuild=true /p:DeployDefaultTarget=WebPublish /p:WebPublishMethod=FileSystem /p:SkipInvalidConfigurations=true /t:build /p:Configuration=Release /p:Platform=\"Any CPU\" /p:DeleteExistingFiles=True /p:publishUrl=c:\\inetpub\\wwwroot\ip_help1"
    					}
				}
			}
}
