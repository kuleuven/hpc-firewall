#!/usr/bin/env groovy
buildGo{
  docker=true
}

stage("Deploy") {
  build job: '/team-hpc/nomadjobs/hpc-firewall/', wait: false, parameters: [
  [$class: 'StringParameterValue', name: 'Tier', value: 'quality']
  ]
}
