#!/bin/env bash
#
# 时间: 2023-2-1
# 版本: 0.5
# 作者: li
#
# 脚本名称： 
# 脚本灵感来源: 
# 脚本可以完成的任务：
# 1. 从腾讯平台抓取最新的数据
# 2. 抓取详细数据
# 3. 通过 webhook 推送到飞书机器人

# 脚本使用： 
# 配合 crontab 使用

contentDir=/tmp/softwareUpdateInfo/
curlHeader="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
dateTimeNow=`date +%Y%m%d%H%M`
tmpFilePath=${contentDir}"tmpFile"${dateTimeNow}
resDataFilePath=${contentDir}"resDataFile"${dateTimeNow}
resDataFilePath1=${contentDir}"resDataFile1"${dateTimeNow}
todayResDataFilePath=${contentDir}"todayResDataFile"
feishuWebhook="your feishu roboat webhook"
todayDate=$(date +"%Y-%m-%d")

if [ ! -d $contentDir ];then
  mkdir $contentDir
fi

curl -s -o "$tmpFilePath" https://security.tencent.com/index.php/ti
sed -i "/csrf_token/d" ${tmpFilePath}

# find 注意需要排除某些文件
find  ${contentDir}*  -not -path ${todayResDataFilePath} -cmin  +120 -exec rm {} \;

# 检查文件内容是否一致
function checkContentDiff(){
  local fileName=$1$(date +"%Y%m%d")
  local tmpFileArray=($(find ${contentDir} -type f -name "$fileName*"))

  if [ ${#tmpFileArray[@]} -ge 2 ];then
      res=$(md5sum  ${tmpFileArray[*]} | awk '{print $1}' | sort | uniq | wc -l)
      if [ $res -eq 1 ];then
        exit 1
      fi
  fi
  unset tmpFileArray
  unset fileName
}

checkContentDiff "tmpFile"

# 数据转化为以下格式内容
# 软件名,感知时间,更新类型,版本,漏洞级别,详情
grep -C 3 '安全更新' ${tmpFilePath} | sed '/<!-- <tr>/,$d' | grep "<td" | sed 's,</tr><tr>,\n,g'  |  sed -r "s#<td[^>]*?>##g" | sed -r "s#</td[^>]*?>\s*#,#g" | sed 's#<a target="_blank" href="#https://security.tencent.com/index.php/#g' | sed 's#">详情</a>,# #g' |  sed 's/^\s*//g'|  awk '{if(NR % 6 == 0) {print $0} else {printf("%s", $0)}}' | grep -E "$(date +"%Y-%m-%d")|$(date +"%Y-%m-%d" -d "-1 day")" > ${resDataFilePath}
# 需要将最后的链接替换为官方链接

function updateResdata(){
  case $1 in
    url)
      res=$(grep -A 2 "来源链接" $tmpFilePath1 | grep "href=" | sed -r "s#<a[^>]*?>##g" | sed -e 's,</a>,,g'  -e 's/^[ ]*//g')
      ;;
    time)
      res=$(grep "感知时间" $tmpFilePath1 |grep -oP '(?<=<span>).*(?=</span>)')
      ;;
    detail)
      res=$(grep -A 2 "更新详情" $tmpFilePath1 | sed '/更新详情/d'|  sed -e  "s/<[^>]*>//g" -e '/^\s*$/d' -e 's/[ ]*$//g' -e 's/^[ ]*//g' -e 's/&amp;nbsp;//g' -e 's/&quot;Language&quot;//g')
      ;;
    *)
      res="error"
      ;;
  esac
  echo $res
}

cat $resDataFilePath |  while  read LINE  
do 
  IFS=','
  read -ra strArr <<<"$LINE"
  dateTimeNow=`date +%Y%m%d%H%M`
  tmpFilePath1=${contentDir}"tmpFile1"${dateTimeNow}
  curl -s -H "User-Agent: $curlHeader" -o "$tmpFilePath1" ${strArr[5]}
  # 下面语句需要手动输入， ^M 在 vi 中 ctrl-v ctrl-m 生成
  sed -i 's/^M/\\n/g' $tmpFilePath1
  sourceUrl=$(updateResdata "url")
  getTime=$(updateResdata "time")
  strArr[6]=$(updateResdata "detail")
  strArr[5]=$sourceUrl
  strArr[1]=$getTime
  IFS=,; echo "${strArr[*]}" >> $resDataFilePath1
  rm -f $tmpFilePath1
done

checkContentDiff "resDataFile"

# 配置飞书消息
function pushMessageModule(){
cat >  ${contentDir}/feishuModule <<-EOF 
{
  "msg_type": "interactive",
  "card": {
    "config": {
      "wide_screen_mode": true
    },
    "elements": [
      {
        "tag": "markdown",
        "content": "**感知时间**: ${pushMessage_date} ${pushMessage_date_time}\n**更新版本**: ${pushMessage_version}\n**风险等级**: ${pushMessage_level}\n**更新详情**: ${pushMessage_detial}\n**情报来源**: 腾讯安全"
      },
      {
        "tag": "action",
        "actions": [
          {
            "tag": "button",
            "text": {
              "tag": "plain_text",
              "content": "官方链接"
            },
            "type": "danger",
            "multi_url": {
              "url": "${pushMessage_url}",
              "pc_url": "",
              "android_url": "",
              "ios_url": ""
            }
          }
        ]
      }
    ],
    "header": {
      "template": "carmine",
      "title": {
        "content": "${pushMessage_software} ${pushMessage_type}",
        "tag": "plain_text"
      }
    }
  }
}
EOF
}

# 检测官方链接是否正常是否正常
function urlCheck(){
  # block_list
  http_code=$(curl -sL -w "%{http_code}"  "${pushMessage_url}" -o /dev/null)
  if [[ $http_code -eq 200 || $http_code -eq 300 || $http_code -eq 301 ]];then
    pushMessageModule
  else
    pushMessage_url=${pushMessage_url/http/https}
    grep "https://" ${pushMessage_url} > /dev/null
    if [[ $? -ne 0 ]];then
      http_code=$(curl -sL -w "%{http_code}"  "${pushMessage_url}" -o /dev/null)
      if [[ $http_code -eq 200 || $http_code -eq 300 || $http_code -eq 301 ]];then
        pushMessageModule
      else
        pushMessageModule
        sed -i "s/腾讯安全/&<br>官方链接有问题,请等待进一步确认/" ${contentDir}feishuModule
      fi
    else
        sed -i "s/腾讯安全/&\\n官方链接有问题,请等待进一步确认/" ${contentDir}feishuModule
    fi
  fi
}

# 获取当天的记录
tmpFilePath2=${contentDir}"tmpFile2"${dateTimeNow}
grep "${todayDate}" ${resDataFilePath1} > ${tmpFilePath2}

if [ ! -s $tmpFilePath2 ]; then 
  exit 1
fi 

if [ ! -f $todayResDataFilePath ];then
  touch ${todayResDataFilePath}
fi

grep -vFf ${todayResDataFilePath} ${tmpFilePath2}
if [[ $? -ne 0 ]];then
  exit 1
fi


pushMessage=$(diff $tmpFilePath2 ${todayResDataFilePath} | grep "<"| sed 's/< //g' |tr '\n' ',' | sed 's/,$//' )

pushMessageNum=($(diff $tmpFilePath2 ${todayResDataFilePath} | grep "<"| sed 's/< //g' | wc -l ))


IFS=','
read -ra tmpStrArr <<<"$pushMessage"

countMessage=$(echo "${#tmpStrArr[*]}/${pushMessageNum}" | bc)

for (( i=0; i < ${pushMessageNum}; i=i+1 )); do
  pushMessage_software=${tmpStrArr[0+i*$countMessage]}
  pushMessage_date=${tmpStrArr[1+i*countMessage]}
  pushMessage_type=${tmpStrArr[2+i*countMessage]}
  pushMessage_version=${tmpStrArr[3+i*countMessage]}
  pushMessage_level=${tmpStrArr[4+i*countMessage]}
  pushMessage_url=${tmpStrArr[5+i*countMessage]}
  pushMessage_detial=${tmpStrArr[6+i*countMessage]}
  echo "${pushMessage_software},${pushMessage_date},${pushMessage_type},${pushMessage_version},${pushMessage_level},${pushMessage_url},${pushMessage_detial}"  >> ${todayResDataFilePath}

  urlCheck

  curl -X POST -H "Content-Type: application/json" \
    -d @${contentDir}/feishuModule \
    ${feishuWebhook}
done
rm -f $tmpFilePath2

unset todayDate
unset strArr
unset tmpStrArr
unset tmpFileArray
unset countMessage
unset pushMessage
unset tmpFilePath2
