const express = require('express');
const cors = require('cors');
const axios = require("axios");
const https = require('https');
const http = require('http');
const fs = require('fs');
const { log, error } = require('console');

const app = express();

require('dotenv').config();

let raw_capec = fs.readFileSync('capec.json')
let capec = JSON.parse(raw_capec)

let raw_cwe = fs.readFileSync('cwe.json')
let cwe = JSON.parse(raw_cwe)

let raw_response = fs.readFileSync('response.json')
let response = JSON.parse(raw_response)


let capecs = capec.Attack_Pattern_Catalog.Attack_Patterns.Attack_Pattern
let cwes = cwe.Weakness_Catalog.Weaknesses.Weakness
// andrey
TECHNIQUES = [
    '1561.002', '1498.001', '1491.002',
    '1499.001', '1499.003', '1561',
    '1565.001', '1489', '1499.004',
    '1565.003', '1498.002', '1499.002',
    '1491', '1657', '1491.001',
    '1565', '1531', '1486',
    '1499', '1496', '1565.002',
    '1485', '1498', '1495',
    '1490', '1561.001', '1529'
]
// DESC = 'Impact'

response.vulnerabilities.forEach(cve => {
    cve.cve.capecs = []
    cve?.cve?.weaknesses.forEach(cve_cwe => {
        capecs.forEach(capec => {
            let cve_cwe_id = cve_cwe.description[0].value
            let capec_cwe = capec?.Related_Weaknesses?.Related_Weakness
            if (capec_cwe?.length > 1) {
                capec_cwe.forEach(one_capec_cwe => {
                    if (cve_cwe_id === 'CWE-' + one_capec_cwe.CWE_ID) {
                        let obj = {
                            capec: capec
                        }
                        cve.cve.capecs.push(obj)
                    }
                });
            } else {
                if (cve_cwe_id === 'CWE-' + capec_cwe?.CWE_ID) {
                    // console.log(capec_cwe);
                    let obj = {
                        capec: capec
                    }
                    cve.cve.capecs.push(obj)

                }
            }
        });
    });
});


// dima
// TECHNIQUES = [
//     '1558.001', '1550', '1550.002',
//     '1558.003', '1649', '1558.004',
//     '1558', '1550.003', '1003.006',
//     '1033', '1615', '1003',
//     '1484', '1484.001', '1484.002',
//     '1098.005', '1207', '1484',
//     '1484.001', '1556.005', '1134.005',
//     '1531', '1222.001', '1556',
//     '1556.006', '1098', '1207',
//     '1037.003', '1484.002', '1649',
//     '1222', '1484', '1484.001',
//     '1037', '1134'
// ]
// DESC = 'Directory'



let main_json = {
    capecs: []
}

// console.log(response.vulnerabilities);

TECHNIQUES.forEach(T => {
    capecs.forEach(capec => {
        let capec_taxonomy = capec?.Taxonomy_Mappings?.Taxonomy_Mapping
        let cwes = capec?.Related_Weaknesses?.Related_Weakness

        if (capec?.Taxonomy_Mappings?.Taxonomy_Mapping.length !== undefined) {
            capec_taxonomy.forEach(tax => {
                if (tax?.Entry_ID === T) {
                    if (typeof (cwes) === Array) {

                        for (cwe in cwes) {
                            let capec_obj = {
                                capec: {
                                    id: capec?.ID,
                                    name: capec?.Name,
                                    execution_flow: capec?.Execution_Flow?.Attack_Step,
                                    mitigations: capec?.Mitigations?.Mitigation,
                                    cwes: cwe
                                }
                            }
                            main_json.capecs.push(capec_obj)
                            // main_json['capec_id=' + capec.ID].capec_name = capec?.Name
                        }
                    } else {
                        let capec_obj = {
                            capec: {
                                id: capec?.ID,
                                name: capec?.Name,
                                execution_flow: capec?.Execution_Flow?.Attack_Step,
                                mitigations: capec?.Mitigations?.Mitigation,
                                cwes: cwes
                            }
                        }
                        main_json.capecs.push(capec_obj)
                        // main_json['capec_id=' + capec.ID].capec_name = capec?.Name
                    }
                }
            });
        } else {
            if (capec_taxonomy?.Entry_ID === T) {
                if (cwes === Array) {
                    for (cwe in cwes) {
                        let capec_obj = {
                            capec: {
                                id: capec?.ID,
                                name: capec?.Name,
                                execution_flow: capec?.Execution_Flow?.Attack_Step,
                                mitigations: capec?.Mitigations?.Mitigation,
                                cwes: cwe
                            }
                        }
                        main_json.capecs.push(capec_obj)
                        // main_json['capec_id=' + capec.ID].capec_name = capec?.Name

                    }
                } else {
                    let capec_obj = {
                        capec: {
                            id: capec?.ID,
                            name: capec?.Name,
                            execution_flow: capec?.Execution_Flow?.Attack_Step,
                            mitigations: capec?.Mitigations?.Mitigation,
                            cwes: cwes
                        }
                    }
                    main_json.capecs.push(capec_obj)
                    // main_json['capec_id=' + capec.ID].capec_name = capec?.Name

                }
            }
        }
    });
});

function delay(time) {
    return new Promise(resolve => setTimeout(resolve, time));
}
//andrey
let keywordSearch = [
    "DoS vulnerability",
    "buffer overflow vulnerability",
    "command injection vulnerability",
    "XSS vulnerability",
    "RCE vulnerability"
]

//dima

// let keywordSearch = [
//     'Domain controller vulnerability',
//     'Active Directory vulnerability',
//     'Kerberos vulnerability',
//     'LDAP vulnerability',
//     'SMB vulnerability',
//     'DNS vulnerability'
// ]

//valera
// let keywordSearch = [
//     'API',
//     'Web application',
//     'Injection vulnerability',
//     'Authorization vulnerability',
//     'Authentication vulnerability',
//     'Configuration vulnerability'
// ]

// const cwe_list = [
//     "CWE-285",
//     "CWE-639",
//     "CWE-204",
//     "CWE-307",
//     "CWE-770",
//     "CWE-400",
//     "CWE-918",
//     "CWE-209",
//     "CWE-319",
//     "CWE-20",
//     "CWE-200",
//     "CWE-311",
// ]

// let VALERA = {
//     cwes: [
//         { id: "CWE-285" },
//         { id: "CWE-639" },
//         { id: "CWE-204" },
//         { id: "CWE-307" },
//         { id: "CWE-770" },
//         { id: "CWE-400" },
//         { id: "CWE-918" },
//         { id: "CWE-209" },
//         { id: "CWE-319" },
//         { id: "CWE-20" },
//         { id: "CWE-200" },
//         { id: "CWE-311" },
//     ]
// }

// let gonvo = (async function () {
//     for (let huidnex = 0; huidnex < VALERA.cwes.length; huidnex++) {
//         const cwe = VALERA.cwes[huidnex];
//         cwe.cves = {}
//         for (let j = 0; j < keywordSearch.length; j++) {
//             await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev', {
//                 params: {
//                     cweId: cwe.id,
//                     keywordSearch: keywordSearch[j],
//                 },
//                 headers: {
//                     'Accept': "application/json",
//                     'Accept-Encoding': 'gzip, deflate, br',
//                     'apiKey': 'dbb08e42-8751-4b0e-a0fc-078eac1b3cac'
//                 }
//             }).then(res => cwe.cves[keywordSearch[j]] = (res.data.vulnerabilities))
//             await delay(5000);
//         }
//     }



// })();




for (const capec in main_json.capecs) {
    if (Object.hasOwnProperty.call(main_json.capecs, capec)) {
        const c = main_json.capecs[capec];
        const element = c?.capec?.cwes;
        if (element?.length > 1) {
            (async function () {
                for (let index = 0; index < element.length; index++) {
                    const el = element[index];
                    el.cves = {

                    }
                    let data = 'CWE-' + el.CWE_ID
                    await delay(15000);

                    for (let j = 0; j < keywordSearch.length; j++) {
                        await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0?', {
                            params: {
                                cweId: data,
                                keywordSearch: keywordSearch[j],
                            },
                            headers: {
                                'Accept': "application/json",
                                'Accept-Encoding': 'gzip, deflate, br',
                                'apiKey': 'dbb08e42-8751-4b0e-a0fc-078eac1b3cac'
                            }
                        }).then(res => el.cves[keywordSearch[j]] = (res.data.vulnerabilities))
                        await delay(15000);
                    }

                }
            })();

        }
        else if (element?.CWE_ID) {
            (async function () {
                let data = 'CWE-' + element?.CWE_ID
                await delay(15000);

                for (let j = 0; j < keywordSearch.length; j++) {
                    element.cves = {}
                    await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0?', {
                        params: {
                            cweId: data,
                            keywordSearch: keywordSearch[j],
                        },
                        headers: {
                            'Accept': "application/json",
                            'Accept-Encoding': 'gzip, deflate, br',
                            'apiKey': 'dbb08e42-8751-4b0e-a0fc-078eac1b3cac'
                        }
                    }).then(res => element.cves[keywordSearch[j]] = (res.data.vulnerabilities))
                    await delay(15000);
                }
            })();

            // console.log(element);
        }
        // if (element?.length > 1) {
        //     element.forEach(el => {
        //         el.data = []
        //         cves2023.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }
        //         });
        //         cves2022.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2021.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2020.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2019.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }
        //         });
        //         cves2018.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2017.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2016.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2015.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }
        //         });
        //         cves2014.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2013.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2012.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2011.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }
        //         });
        //         cves2010.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2009.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2008.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2007.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }
        //         });
        //         cves2006.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2005.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2004.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2003.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //         cves2002.forEach(cve => {
        //             if (cve.cve?.problemtype?.problemtype_data[0]?.description[0]?.value === 'CWE-' + el.CWE_ID && cve.cve?.description?.description_data[0]?.value.includes(DESC)) {
        //                 let obj = {
        //                     cve_id: cve.cve?.CVE_data_meta.ID,
        //                     cve_value: cve.cve?.description?.description_data[0]?.value,
        //                     baseMetricV2: cve?.impact?.baseMetricV2,
        //                     baseMetricV3: cve?.impact?.baseMetricV3
        //                 }
        //                 el.data.push(obj)
        //             }

        //         });
        //     });
        // }
        // else {
        //     if (element?.CWE_ID) {
        //         // element.cve = cve_info('CWE-' + element.CWE_ID, 'Active Directory')
        //     }
        // }
    }

}

app.use(express.json());
app.use(cors());

app.get('/', async (req, res) => {

    res.status(200).json(response.vulnerabilities)
}
)

app.get('/main_json', async (req, res) => {
    res.status(200).json(main_json)
    // console.log(r.data);
}
)
app.get('/valera', async (req, res) => {
    res.status(200).json(VALERA)
    // console.log(r.data);
}
)


const PORT = 8000;

app.listen(PORT, () => console.log('server started on PORT ' + PORT))