#!/bin/bash
#######Perform IaC scan###########
#echo "Entered full cloned repo path:" $1

if [[ "$1" != "" ]];then
    repo_path=$1
else
    echo "Please enter the full cloned repository path on build server/runner. For details refer to https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
    exit 1;
fi
#echo "repo_path:" $repo_path
#ls -al $repo_path

#read ENV variables
echo $prisma_cloud_api_url $prisma_cloud_access_key #$prisma_cloud_secret_key

if [[ -z "$prisma_cloud_api_url" ]];then
  echo "Please enter a valid URL. For details refer to https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
  exit 1;
fi
if [[ -z "$prisma_cloud_access_key" || -z "$prisma_cloud_secret_key" ]];then
  echo "Invalid credentials, verify that access key and secret key in environment variables are valid. For details refer to https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
  exit 1;
fi

if [[ ! -f $repo_path/.prismaCloud/config.yml ]]; then
  echo "Can not find config.yml under .prismaCloud folder in repo $CI_PROJECT_TITLE. Please make sure the file is present in correct format https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html at the root of your repo under .prismaCloud folder."
  exit 1;
fi

if [[ -z "$prisma_cloud_cicd_asset_name" ]]; then
  echo "Please enter a valid cicd asset name. For details refer to https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
  exit 1;
fi


#####Compress the repo and check if compressed zip file size>5MB#############
#echo "current path:"
#pwd

cd $repo_path
#ls -al .
zip -r iacscan.zip . -x \*.git\* #here cd inside repo_path and '.' as source is mandatory else while zipping copies else it will zip from root instead of files inside repo
#echo "after zip content of repo_path"
#ls -al $repo_path

file_size="$(wc -c iacscan.zip | awk '{print $1}')"
#echo "file_size:" $file_size
file_size_limit=5242880
if [[ "$file_size" -gt "$file_size_limit" ]];then
  echo "Directory size $repo_path more than 8MB is not supported"
  exit 1;
fi

#$CI_PROJECT_DIR is default inbuilt dir used to upload the artifacts but you can change to any one the job has access to.
#echo "view content of CI_PROJECT_DIR"
#ls -al $CI_PROJECT_DIR

#############Check failure criteria exists, if not default 0,0,0,or#########
if [[ -z "$prisma_cloud_cicd_failure_criteria" ]];then
  failure_criteria_high_severity=0
  failure_criteria_medium_severity=0
  failure_criteria_low_severity=0
  failure_criteria_operator="or"
else
  echo "failure criteria:" $prisma_cloud_cicd_failure_criteria
  cicd_failure_criteria_removed_spaces=$(printf '%s' $prisma_cloud_cicd_failure_criteria)
#-   echo $cicd_failure_criteria_removed_spaces
  delimiter=,
  s=$cicd_failure_criteria_removed_spaces$delimiter
  array=();
  while [[ $s ]]; do
    array+=( "${s%%"$delimiter"*}" );
    s=${s#*"$delimiter"};
  done;
#-   declare -p array
  failure_criteria_high_severity=$(awk -F':' '{print $2}' <<< "${array[0]}")
  failure_criteria_medium_severity=$(awk -F':' '{print $2}' <<< "${array[1]}")
  failure_criteria_low_severity=$(awk -F':' '{print $2}' <<< "${array[2]}")
  failure_criteria_operator=$(awk -F':' '{print $2}' <<< "${array[3]}")
  #echo "Failure Criterias:" $failure_criteria_high_severity $failure_criteria_medium_severity $failure_criteria_low_severity $failure_criteria_operator
fi

#################################################
# Read .prismaCloud/config.yml and form headers for scan
################################################

fileContents=$(/home/yq read -j .prismaCloud/config.yml)
#echo "file contents are:" $fileContents
t_Type="$(echo "$fileContents" | jq -r '.template_type')"
#echo "template type:" $t_Type
headers=""
url=""

if [[ ! -z "$t_Type" ]]; then
  templateType=${t_Type^^}
  #echo $templateType
else
   echo "No valid template-type found in config.yml file in repo $CI_PROJECT_TITLE. Please specify either of these values: TF, CFT or K8s as template-type variable in the config.yml"
   exit 1;
fi


if [[ "$templateType" == "TF" ]]; then
   url="$prisma_cloud_api_url/iac/tf/v1/scan"
   terraformVersion="$(echo "$fileContents" | jq -r '.terraform_version')"
   if [[ ! -z "$terraformVersion" && "$terraformVersion" == "0.12" ]];then
     headers+=" -H terraform-version:$terraformVersion"
#read terraform 0.12 parameters
     isTerraform12ParamsPresent="$(echo "$fileContents" | jq -r '.terraform_012_parameters')"
     if [[ "$isTerraform12ParamsPresent" != null ]]; then
       terraformContents="$(echo "$fileContents" | jq -r '.terraform_012_parameters[] |= with_entries( .key |= gsub("root_module"; "root-module") )' | jq -r '.terraform_012_parameters[] |= with_entries( .key |= gsub("variable_files"; "variable-files") )' )"
       terraform012Parameters="$(echo "$terraformContents" | jq -r '.terraform_012_parameters' | tr -d '\n\t' | tr -d '[:blank:]')"
       if [[  "$terraform012Parameters" != null ]]; then
         headers+=" -H terraform-012-parameters:$terraform012Parameters"
       fi
     fi
   else
#-      headers+=" -H terraform-version:0.11" no version header needed for 0.11
#-      read terraform 0.11 parameters
     variableFiles="$(echo "$fileContents" | jq -r '.terraform_011_parameters.variable_files')"
     variableValues="$(echo "$fileContents" | jq -r '.terraform_011_parameters.variable_values')"
     if [[ "$variableFiles" != null ]]; then
       headers+=" -H 'rl-variable-file-names:$variableFiles'"
     fi
     if [[ "$variableValues" != null ]]; then
       headers+=" -H rl-parameters:$variableValues"
     fi
   fi
elif [[ "$templateType" == "CFT" ]]; then
   url="$prisma_cloud_api_url/iac/cft/v1/scan"
   variableValues="$(echo "$fileContents" | jq -r '.cft_parameters.variable_values' | tr -d '\n\t' | tr -d '[:blank:]')"
   if [[ "$variableValues" != null ]]; then
     headers+=" -H 'rl-parameters:$variableValues'"
   fi
elif [[ "$templateType" == "K8S" ]]; then
   url="$prisma_cloud_api_url/iac/k8s/v1/scan"
else
   echo "No valid template-type found in config.yml file in repo $CI_PROJECT_TITLE. Please specify either of these values: TF, CFT or K8s as template-type variable in the config.yml"
   exit 1;
fi

###################################################
#  LOGIN TO GET TOKEN
##################################################
#echo "Get token using login api"

result=$(curl -k -i -o -X POST https://$prisma_cloud_api_url/login --user-agent "GitLab PrismaCloud/DevOpsSecurity-1.0.0" -H 'Content-Type:application/json' -d "{\"username\":\"${prisma_cloud_access_key}\",\"password\":\"${prisma_cloud_secret_key}\"}")
#echo $result
code=$(echo "$result" |grep HTTP | awk '{print $2}')
echo $code

if [[ "$code" -eq 400 || "$code" -eq 401 || "$code" -eq 403 ]]; then
  echo "Invalid credentials, verify that access key and secret key in environment variables are valid. For details refer to https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
  exit 1;
elif [[ "$code" -eq 500 || "$code" -eq 501 || "$code" -eq 503 ]];then
  echo "Oops! Something went wrong, please try again or refer to documentation https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
  exit 1;
elif [[ "$code" -ne 200 ]];then
  echo "Oops! Something went wrong, please try again or refer to documentation https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/prisma-cloud-devops-security/use-the-prisma-cloud-app-for-gitlab.html"
  exit 1;
fi

output_response=$(echo "$result" | grep token)

token="$(echo "$output_response" | jq  .token | tr -d '"')"

####################################################
# Start PROCESSING PRISM CLOUD IAC SCAN
###################################################
#echo url:"$url"
echo header:"$headers"

#form prisma-tags
prisma_tags=""

if [[ ! -z "$prisma_cloud_cicd_tags" ]]; then
  temp_str=$(printf '%s' $prisma_cloud_cicd_tags)
  if [[ ! -z "$temp_str" ]]; then
    settings_tags=\"$(sed 's/,/","/g' <<< "$temp_str")\"
    prisma_tags="\"settings-tags\":[$settings_tags]"
  fi
fi

#tags from config.yml
repo_tags="$(echo "$fileContents" | jq -r '.tags' |tr -d '\n\t' | tr -d '[:blank:]')"
if [[ $repo_tags != null ]]; then
  prisma_tags+=",\"repo-tags\":$repo_tags"
fi

##################################################################
# creating metadata structure
metadata_json={"asset-name":"$prisma_cloud_cicd_asset_name","asset-type":"Gitlab","user-id":"${GITLAB_USER_LOGIN}","prisma-tags":{"$prisma_tags"},"scan-attributes":{"build-number":"${CI_JOB_ID}","project-name":"${CI_PROJECT_TITLE}"},"failure-criteria":{"high":"$failure_criteria_high_severity","medium":"$failure_criteria_medium_severity","low":"$failure_criteria_low_severity","operator":"$failure_criteria_operator"}}
#echo metadata "$metadata_json"
#################################################################

#cd  $CI_BUILDS_DIR
echo "Current working directory $PWD"
ls
#cp /home/$repo_path/iacscan.zip .
response="$(curl -k  -X POST https://$url -H "x-redlock-auth:${token}" --user-agent "GitlabCI PrismaCloud/DevOpsSecurity-1.0.0" $headers -H "x-redlock-iac-metadata:${metadata_json}" -F templateFile=@iacscan.zip)"
echo $response

result="$(echo "$response" | jq -r '.result.is_successful')"
mkdir results
if [[ "$result" == true ]];then
  matched="$(echo "$response" | jq -r '.result.rules_matched')"
  if [[ $matched != null ]];then
    stats="$(echo "$response" | jq -r '.result.severity_stats')"
    echo $matched | jq '["Severity","Name","Description", "Files"], (map({severity, name, description, files} ) | .[] | [.severity, .name, .description, (.files|join(";"))]) | @csv' | tr -d '\\"'> results/scan.csv
    awk -F'\t' -v OFS='\t' '
      NR == 1 {print "Index", $0; next}
      {print (NR-1), $0}
    ' results/scan.csv > results/scan_results.csv

    #format console output file to display
    echo $matched |  jq '["Severity","Name","Files"], (map({severity, name, files} ) | .[] | [.severity, .name, (.files|join(";"))]) | @csv'| column -t -s "," | tr -d '\\"' > results/formatted.csv
    awk -F'\t' -v OFS='\t' '
      NR == 1 {print "\nIndex", $0; print "------------------------------------------------------------------------------------------------------------------------------------------------------" ;  next}
      {print (NR-1), $0}
    ' results/formatted.csv > results/console_output.csv
    #show result on console
    cat results/console_output.csv

    #echo $CI_PROJECT_DIR
    mkdir $CI_PROJECT_DIR/report
    cp -r results/scan_results.csv $CI_PROJECT_DIR/report
    #ls -la $CI_PROJECT_DIR/report


    high="$(echo "$stats" | jq -r '.high')"
    med="$(echo "$stats" | jq -r '.medium')"
    low="$(echo "$stats" | jq -r '.low')"
    if [[ ( ( $failure_criteria_operator == "or" ) && ( "$high" -ge $failure_criteria_high_severity) || ( "$medium" -ge $failure_criteria_medium_severity ) || ( "$low" -ge $failure_criteria_low_severity ) ) || ( ($failure_criteria_operator == "and") && ( "$high" -ge $failure_criteria_high_severity ) && ( "$medium" -ge $failure_criteria_medium_severity ) && ( "$low" -ge $failure_criteria_low_severity ) ) ]];then
     echo "Prisma Cloud IaC scan failed with issues as security issues count (high:$high , medium:$med , low:$low) meets or exceeds the failure criteria (high:$failure_criteria_high_severity, medium:$failure_criteria_medium_severity, low:$failure_criteria_low_severity, operator:$failure_criteria_operator) "
     exit 1;
    else
     echo "Prisma Cloud IaC Scan has been successful as security issues count (high:$high, medium:$med, low:$low) does not exceed the failure criteria (high:$failure_criteria_high_severity, medium:$failure_criteria_medium_severity, low:$failure_criteria_low_severity, operator:$failure_criteria_operator)"
     echo "Prisma Cloud IaC Scan has been successful as security issues count (high:$high, medium:$med, low:$low) does not exceed the failure criteria (high:$failure_criteria_high_severity, medium:$failure_criteria_medium_severity, low:$failure_criteria_low_severity, operator:$failure_criteria_operator)" >> $repo_path/tmp_file.txt
     exit 0;
    fi
  else
    echo "Good job! Prisma Cloud did not detect any issues."
  fi
else
  error_message="$(echo "$response" | jq -r '.result.error_details')"
  echo "$error_message"
  exit 1;
fi
