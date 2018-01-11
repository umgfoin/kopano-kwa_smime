#!/usr/bin/env groovy

pipeline {
	agent none
	stages {
		stage('Test') {
			agent {
				dockerfile true
			}
			steps {
					sh 'phpunit -c unittest.xml'
					junit 'smime-phptests.xml'
					script {
						if (env.BRANCH_NAME == 'master') {
							publishHTML([allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'htmlcov', reportFiles: 'index.html', reportName: 'HTML Report', reportTitles: ''])
						}
					}
			}
		}
	}
}
