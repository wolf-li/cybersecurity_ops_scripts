#!/bin/bash
# version: 0.6
# auth: wolf-li
# usage:
#     ./vuln_search.sh
# 

read -p ">>>>> 输入要搜索的软件名: " software
read -p ">>>>> 输入要搜索的软件版本: " software_version

date_time_now=$(date +%F-%H_%M)
dir_name=${software}_${software_version}_vuln_collection_${date_time_now}
mkdir ${dir_name}

cve_result_file=./${dir_name}/cve-${software}-${software_version}
cnnvd_result_file=./${dir_name}/cnnvd-${software}-${software_version}
count_type=''
result1=./${dir_name}/vuln-${software}-report-${date_time_now}-wps.csv
result2=./${dir_name}/vuln-${software}-report-${date_time_now}-excel.csv
cve_num=0

old_cnnvd_url='http://123.124.177.30'
old_cnnvd_url_getcnnvdnum='http://123.124.177.30/web/vulnerability/queryLds.tag'
cnnvd_url='https://www.cnnvd.org.cn/home/globalSearch?keyword='

function get_cve_num(){
    curl -C - --retry 10 -s -o ./${dir_name}/tmp_file1  "https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword=${software}+${software_version}"

    args=($(grep -B 10 "View CVEs" ./${dir_name}/tmp_file1 | grep "query=cpe" | cut -d';' -f 5 | awk '{print $1}'| sed s/\"//g))
    if [ ${#args[@]} -gt 1 ];then
        get_cve_url="https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&isCpeNameSearch=true&seach_type=all&"${args[-1]}
        curl -C - --retry 10 -s -o ${dir_name}/tmp_file2 ${get_cve_url[0]}
        
        cve_num=$(grep "vuln-matching-records-count" ${dir_name}/tmp_file2 |grep -o '>.*<' | sed -e s/\<//g -e s/\>//g)
        if [ ${cve_num} -gt  20 ];then
            echo "CVE 漏洞数量: ${cve_num}, 由于漏洞数据量过多，仅收集前 20 个！！！ "
            grep "/vuln/detail/CVE" ${dir_name}/tmp_file2 | grep -oP "CVE-\d{4}-\d{1,8}" > ${cve_result_file}
        else
            echo "CVE 漏洞数量: ${cve_num} "
            grep "/vuln/detail/CVE" ${dir_name}/tmp_file2 | grep -oP "CVE-\d{4}-\d{1,8}" > ${cve_result_file}
        fi
    elif  [ ${#args[@]} -eq 1 ];then
        get_cve_url="https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&isCpeNameSearch=true&seach_type=all&"${args[0]}
        curl -C - --retry 10 -s -o ${dir_name}/tmp_file2 ${get_cve_url[0]}
        
        cve_num=$(grep "vuln-matching-records-count" ${dir_name}/tmp_file2 |grep -o '>.*<' | sed -e s/\<//g -e s/\>//g)
        if [ ${cve_num} -gt  20 ];then
            echo "CVE 漏洞数量: ${cve_num}, 由于漏洞数据量过多，仅收集前 20 个！！！ "
            grep "/vuln/detail/CVE" ${dir_name}/tmp_file2 | grep -oP "CVE-\d{4}-\d{1,8}" > ${cve_result_file}
        else
            echo "CVE 漏洞数量: ${cve_num} "
            grep "/vuln/detail/CVE" ${dir_name}/tmp_file2 | grep -oP "CVE-\d{4}-\d{1,8}" > ${cve_result_file}
        fi
    else
        touch ${cve_result_file}
    fi
    rm -f ./${dir_name}/tmp_file*
}


function get_cnnvd_info(){
    num=1
    while read LINE
    do
        post_table="CSRFToken=&cvHazardRating=&cvVultype=&qstartdateXq=&cvUsedStyle=&cvCnnvdUpdatedateXq=&cpvendor=&relLdKey=&hotLd=&isArea=&qcvCname=&qcvCnnvdid=${LINE}&qstartdate=&qenddate="
        curl -C - -s -A "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Edg/100.0.1185.44"  -H "Content-Type: application/x-www-form-urlencoded"  -e "$old_cnnvd_url_getcnnvdnum"  -k -X POST -d "$post_table" "$old_cnnvd_url_getcnnvdnum" > tmp_file_cnnvd

        # cnnvd 编号
        cnnvd_id=($(grep -oP "CNNVD-\d{6}-\d{1,7}" tmp_file_cnnvd | sort |uniq))

        # 部分漏洞 cnnvd 没有收录 查找后会有多个 cnnvd 编号出现
        if [ ${#cnnvd_id[@]} -eq 1 ];then
            echo ${cnnvd_id}  >> ${cnnvd_result_file}
            curl -C - -s ${old_cnnvd_url}/web/xxk/ldxqById.tag?CNNVD=${cnnvd_id} > tmp_file
            # 危害漏洞
            hazard_rating=$(grep "危害等级" tmp_file | grep  ">*-->" | awk -F'>' '{print $(NF-1)}'  | sed s/--//g)
            # 漏洞信息
            vulnerability_information=$(grep -A 10 "漏洞简介" tmp_file | grep -A 3 "<p" | sed  's/<[^>]*>//g'  | sed -e 's/\t//g' -e  '/^\s*$/d')
            # 补丁信息
            patch_information=$(grep -E "^http|https://" tmp_file | grep -vE "链接:|<")

            echo ${num},${software},${software_version},${cnnvd_id},${LINE},${hazard_rating},${vulnerability_information},${patch_information}, >> ${result1}
            
            let num+=1
        else
            echo ${LINE}" CNNVD未收录" >> ${cnnvd_result_file}
            continue
        fi
    done < ${cve_result_file}

    vuln_type=($(grep "危" ${result1} | grep -v "危害等级：" |sort |uniq))

    for vuln_t in ${vuln_type[*]};do
            count_type+=${vuln_t}","$( grep ${vuln_t}  ${result1}  | wc -l )','
    done

    sed -i '1i\编号,软件名称,版本,CNNVD 编号,CVE 编号,危害等级,漏洞简介,补丁信息,' ${result1}
    rm -f tmp_file*

    echo "CNNVD 数量："$(wc -l ${cnnvd_result_file} | awk '{print $1}' )
}


function main(){
    get_cve_num
    if  test -s ${cve_result_file} ;then
            get_cnnvd_info
    else
            echo "${software} ${software_version} no vuln"
            exit 1
    fi

    iconv -f utf-8 -t gb2312 ${result1} > ${result2}
    echo "windows WPS 可以直接打开："${result1}
    echo "windows Execl 可以直接打开："${result2}
    unset cve_result_file
    unset count_type
    unset cnnvd_file
    unset result
}

main
