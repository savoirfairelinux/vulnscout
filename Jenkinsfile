#!/usr/bin/env groovy

pipeline {
    agent { node { label 'cqfd && ryzen' } }
    stages {
        stage("Checkout and Init") {
            steps {
                sh '''
                    git submodule update --init --force --recursive
                    cqfd init
                '''
            }
        }
        stage("Unit Tests") {
            steps {
                sh 'cqfd -b jenkins_test run'
            }
        }
        stage("Publish Junit Test Results") {
            steps {
                junit checksName: 'pytest and jest', stdioRetention: '', testResults: 'junit*.xml'
            }
        }
        stage("Test docker image") {
            steps {
                script {
                    def dockerImage = docker.build("vulnscout:${BUILD_TAG}")
                    sh '''
                        chmod +x tests/docker/testDocker.sh
                        tests/docker/testDocker.sh "vulnscout:${BUILD_TAG}"
                    '''
                }
            }
        }
    }
    post {
        success {
            cleanWs()
        }
    }
}
