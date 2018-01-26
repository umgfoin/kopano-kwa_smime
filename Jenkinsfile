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
		stage('ESLint') {
			agent {
				docker {
					image 'node:9'
					args '-u 0'
				}
			}
			steps {
				sh 'npm install -g eslint'
				sh 'eslint -f junit -o eslint.xml js || true'
				junit 'eslint.xml'
			}
		}
	}
}
