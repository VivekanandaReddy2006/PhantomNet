import{i as e}from"./iframe-CMJCcvwf.js";import{n as t,t as n}from"./jsx-runtime-Eaml7RB7.js";import{t as r}from"./prop-types-DVIbkB0r.js";var i=e(r(),1),a=e(t(),1),o=n(),s=[{id:`initial-access`,label:`Initial Access`},{id:`execution`,label:`Execution`},{id:`persistence`,label:`Persistence`},{id:`privilege-escalation`,label:`Privilege Escalation`},{id:`defense-evasion`,label:`Defense Evasion`},{id:`credential-access`,label:`Credential Access`},{id:`discovery`,label:`Discovery`},{id:`lateral-movement`,label:`Lateral Movement`},{id:`collection`,label:`Collection`},{id:`command-and-control`,label:`Command and Control`},{id:`exfiltration`,label:`Exfiltration`},{id:`impact`,label:`Impact`}],c={"initial-access":[{id:`T1190`,name:`Exploit Public-Facing Application`},{id:`T1566`,name:`Phishing`},{id:`T1078`,name:`Valid Accounts`},{id:`T1133`,name:`External Remote Services`},{id:`T1189`,name:`Drive-by Compromise`},{id:`T1195`,name:`Supply Chain Compromise`}],execution:[{id:`T1059`,name:`Command & Scripting Interpreter`},{id:`T1204`,name:`User Execution`},{id:`T1053`,name:`Scheduled Task/Job`},{id:`T1569`,name:`System Services`},{id:`T1106`,name:`Native API`},{id:`T1047`,name:`Windows Management Instrumentation`}],persistence:[{id:`T1547`,name:`Boot or Logon Autostart`},{id:`T1053`,name:`Scheduled Task/Job`},{id:`T1136`,name:`Create Account`},{id:`T1543`,name:`Create or Modify System Process`},{id:`T1546`,name:`Event Triggered Execution`},{id:`T1098`,name:`Account Manipulation`}],"privilege-escalation":[{id:`T1068`,name:`Exploitation for Privilege Escalation`},{id:`T1548`,name:`Abuse Elevation Control`},{id:`T1055`,name:`Process Injection`},{id:`T1574`,name:`Hijack Execution Flow`},{id:`T1053`,name:`Scheduled Task/Job`},{id:`T1547`,name:`Boot or Logon Autostart`}],"defense-evasion":[{id:`T1027`,name:`Obfuscated Files or Info`},{id:`T1070`,name:`Indicator Removal`},{id:`T1036`,name:`Masquerading`},{id:`T1218`,name:`System Binary Proxy Execution`},{id:`T1112`,name:`Modify Registry`},{id:`T1562`,name:`Impair Defenses`}],"credential-access":[{id:`T1003`,name:`OS Credential Dumping`},{id:`T1110`,name:`Brute Force`},{id:`T1555`,name:`Credentials from Password Stores`},{id:`T1552`,name:`Unsecured Credentials`},{id:`T1056`,name:`Input Capture`},{id:`T1558`,name:`Steal or Forge Kerberos Tickets`}],discovery:[{id:`T1082`,name:`System Information Discovery`},{id:`T1083`,name:`File and Directory Discovery`},{id:`T1018`,name:`Remote System Discovery`},{id:`T1046`,name:`Network Service Discovery`},{id:`T1057`,name:`Process Discovery`},{id:`T1087`,name:`Account Discovery`}],"lateral-movement":[{id:`T1021`,name:`Remote Services`},{id:`T1570`,name:`Lateral Tool Transfer`},{id:`T1091`,name:`Replication Through Removable Media`},{id:`T1550`,name:`Use Alternate Auth Material`},{id:`T1563`,name:`Remote Service Session Hijacking`},{id:`T1210`,name:`Exploitation of Remote Services`}],collection:[{id:`T1114`,name:`Email Collection`},{id:`T1056`,name:`Input Capture`},{id:`T1005`,name:`Data from Local System`},{id:`T1115`,name:`Clipboard Data`},{id:`T1125`,name:`Video Capture`},{id:`T1560`,name:`Archive Collected Data`}],"command-and-control":[{id:`T1071`,name:`Application Layer Protocol`},{id:`T1095`,name:`Non-Application Layer Protocol`},{id:`T1573`,name:`Encrypted Channel`},{id:`T1105`,name:`Ingress Tool Transfer`},{id:`T1090`,name:`Proxy`},{id:`T1219`,name:`Remote Access Software`}],exfiltration:[{id:`T1041`,name:`Exfiltration Over C2 Channel`},{id:`T1020`,name:`Automated Exfiltration`},{id:`T1048`,name:`Exfiltration Over Alt Protocol`},{id:`T1567`,name:`Exfiltration to Cloud Storage`},{id:`T1052`,name:`Exfiltration Over Physical Medium`},{id:`T1030`,name:`Data Transfer Size Limits`}],impact:[{id:`T1485`,name:`Data Destruction`},{id:`T1486`,name:`Data Encrypted for Impact`},{id:`T1489`,name:`Service Stop`},{id:`T1529`,name:`System Shutdown/Reboot`},{id:`T1490`,name:`Inhibit System Recovery`},{id:`T1498`,name:`Network Denial of Service`}]},l=e=>!e||e<=0?`none`:e<=3?`low`:e<=8?`medium`:`high`,u=({techniqueFrequencies:e=null,techniquesData:t=null,data:n=null,placeholderCount:r=6,onCellClick:i=null,onTechniqueClick:u=null,selectedTechniqueId:d=null})=>{let[f,p]=a.useState(null),m=d??f,h=e||t||n,g=a.useMemo(()=>{if(!h)return{};if(Array.isArray(h))return h.reduce((e,t)=>{let n=t.id||t.technique_id||t.techniqueId,r=t.count??t.frequency??t.hits??0;return n&&(e[n]=r),e},{});if(typeof h==`object`){let e={};return Object.entries(h).forEach(([t,n])=>{typeof n==`number`?e[t]=n:Array.isArray(n)?n.forEach(t=>{let n=t.technique_id||t.id||t.techniqueId,r=t.count??t.frequency??t.hits??0;if(n&&(e[n]=r,typeof n==`string`&&n.includes(`.`))){let t=n.split(`.`)[0];e[t]=(e[t]||0)+r}}):n&&typeof n==`object`&&(e[t]=n.count??n.frequency??n.hits??0)}),e}return{}},[h]),_=a.useMemo(()=>{let e={};return h&&(Array.isArray(h)?h.forEach(t=>{let n=t.id||t.technique_id||t.techniqueId;n&&(e[n]=t)}):typeof h==`object`&&Object.values(h).forEach(t=>{if(Array.isArray(t))t.forEach(t=>{let n=t.technique_id||t.id||t.techniqueId;if(n){e[n]=t;let r=n.split(`.`)[0];e[r]||(e[r]=t)}});else if(t&&typeof t==`object`){let n=t.id||t.technique_id||t.techniqueId;n&&(e[n]=t)}})),e},[h]),v=(e,t,n,r)=>{let a=m===t.id;p(a?null:t.id);let o={tacticId:e,...t,count:n,heatLevel:r,isSelected:!a};u&&u(a?null:o),i&&i(e,a?null:o)},y=(e,t,n,r,i)=>{(e.key===`Enter`||e.key===` `)&&(e.preventDefault(),v(t,n,r,i))};return(0,o.jsx)(`div`,{className:`mitre-matrix-container`,children:(0,o.jsx)(`div`,{className:`mitre-matrix-grid`,children:s.map(e=>{let t=c[e.id]||[],n=t.slice(0,Math.max(r,t.length)),i=0,a=0;return n.forEach(e=>{let t=g[e.id]||0;t>0&&(i+=1,a+=t)}),(0,o.jsxs)(`div`,{className:`tactic-column`,children:[(0,o.jsxs)(`div`,{className:`tactic-header tactic-${e.id}`,children:[(0,o.jsx)(`span`,{className:`tactic-title`,children:e.label}),(0,o.jsx)(`span`,{className:`tactic-count-badge`,children:i>0?`${i} Techs (${a})`:`0 Techs`})]}),n.map((t,n)=>{let r=g[t.id]||0,i=l(r),a=m===t.id,c=_[t.id]||{},u=c.description||`No description available for this technique.`,d=c.severity||`MEDIUM`,f=n<3?`pos-bottom`:`pos-top`,p=`align-center`;return e.id===s[0].id?p=`align-left`:e.id===s[s.length-1].id&&(p=`align-right`),(0,o.jsxs)(`div`,{className:`technique-cell heat-${i} ${a?`selected`:``}`,onClick:()=>v(e.id,t,r,i),onKeyDown:n=>y(n,e.id,t,r,i),role:`button`,tabIndex:0,"aria-pressed":a,title:``,children:[(0,o.jsxs)(`div`,{className:`technique-cell-top`,children:[(0,o.jsx)(`span`,{className:`technique-id`,children:t.id}),(0,o.jsx)(`span`,{className:`heat-count-chip`,children:r})]}),(0,o.jsx)(`span`,{className:`technique-name`,children:t.name}),(0,o.jsxs)(`div`,{className:`technique-tooltip ${f} ${p}`,onClick:e=>e.stopPropagation(),children:[(0,o.jsxs)(`div`,{className:`tech-tooltip-header`,children:[(0,o.jsx)(`span`,{className:`tech-tooltip-id`,children:t.id}),(0,o.jsx)(`span`,{className:`tech-tooltip-severity ${d.toLowerCase()}`,children:d})]}),(0,o.jsx)(`div`,{className:`tech-tooltip-name`,children:t.name}),(0,o.jsx)(`p`,{className:`tech-tooltip-desc`,children:u}),(0,o.jsxs)(`div`,{className:`tech-tooltip-footer`,children:[(0,o.jsxs)(`span`,{className:`tech-tooltip-stat`,children:[`Playbooks: `,(0,o.jsx)(`strong`,{children:r})]}),(0,o.jsxs)(`span`,{className:`tech-tooltip-stat`,children:[`Tactic: `,(0,o.jsx)(`strong`,{children:e.label})]})]})]})]},t.id)})]},e.id)})})})};u.propTypes={techniqueFrequencies:i.default.oneOfType([i.default.object,i.default.array]),techniquesData:i.default.oneOfType([i.default.object,i.default.array]),data:i.default.oneOfType([i.default.object,i.default.array]),placeholderCount:i.default.number,onCellClick:i.default.func,onTechniqueClick:i.default.func,selectedTechniqueId:i.default.string};var d=u;u.__docgenInfo={description:`MitreMatrix - MITRE ATT&CK Matrix Heatmap component.\r
Displays 12 standard tactics as column headers and renders technique cells styled\r
with dynamic heat colors corresponding to detection frequency counts.`,methods:[],displayName:`MitreMatrix`,props:{techniqueFrequencies:{defaultValue:{value:`null`,computed:!1},description:``,type:{name:`union`,value:[{name:`object`},{name:`array`}]},required:!1},techniquesData:{defaultValue:{value:`null`,computed:!1},description:``,type:{name:`union`,value:[{name:`object`},{name:`array`}]},required:!1},data:{defaultValue:{value:`null`,computed:!1},description:``,type:{name:`union`,value:[{name:`object`},{name:`array`}]},required:!1},placeholderCount:{defaultValue:{value:`6`,computed:!1},description:``,type:{name:`number`},required:!1},onCellClick:{defaultValue:{value:`null`,computed:!1},description:``,type:{name:`func`},required:!1},onTechniqueClick:{defaultValue:{value:`null`,computed:!1},description:``,type:{name:`func`},required:!1},selectedTechniqueId:{defaultValue:{value:`null`,computed:!1},description:``,type:{name:`string`},required:!1}}};var f={title:`Components/Sentinel/MitreMatrix`,component:d};const p={args:{placeholderCount:6}},m={args:{techniqueFrequencies:{T1190:2,T1059:14,T1053:6,T1068:1,T1027:9,T1003:5,T1082:3,T1021:12,T1114:1,T1071:7,T1041:4,T1486:18}}},h={args:{techniqueFrequencies:[{id:`T1059`,count:24},{id:`T1003`,count:16},{id:`T1021`,count:11},{id:`T1027`,count:15},{id:`T1486`,count:20},{id:`T1190`,count:8}]}};p.parameters={...p.parameters,docs:{...p.parameters?.docs,source:{originalSource:`{
  args: {
    placeholderCount: 6
  }
}`,...p.parameters?.docs?.source}}},m.parameters={...m.parameters,docs:{...m.parameters?.docs,source:{originalSource:`{
  args: {
    techniqueFrequencies: {
      "T1190": 2,
      // Low heat (Initial Access)
      "T1059": 14,
      // High heat (Execution)
      "T1053": 6,
      // Medium heat (Persistence)
      "T1068": 1,
      // Low heat (Privilege Escalation)
      "T1027": 9,
      // High heat (Defense Evasion)
      "T1003": 5,
      // Medium heat (Credential Access)
      "T1082": 3,
      // Low heat (Discovery)
      "T1021": 12,
      // High heat (Lateral Movement)
      "T1114": 1,
      // Low heat (Collection)
      "T1071": 7,
      // Medium heat (C2)
      "T1041": 4,
      // Medium heat (Exfiltration)
      "T1486": 18 // High heat (Impact)
    }
  }
}`,...m.parameters?.docs?.source}}},h.parameters={...h.parameters,docs:{...h.parameters?.docs,source:{originalSource:`{
  args: {
    techniqueFrequencies: [{
      id: "T1059",
      count: 24
    }, {
      id: "T1003",
      count: 16
    }, {
      id: "T1021",
      count: 11
    }, {
      id: "T1027",
      count: 15
    }, {
      id: "T1486",
      count: 20
    }, {
      id: "T1190",
      count: 8
    }]
  }
}`,...h.parameters?.docs?.source}}};const g=[`DefaultScaffold`,`HeatmapMatrixWithFrequencies`,`HighThreatHeatmap`];export{p as DefaultScaffold,m as HeatmapMatrixWithFrequencies,h as HighThreatHeatmap,g as __namedExportsOrder,f as default};