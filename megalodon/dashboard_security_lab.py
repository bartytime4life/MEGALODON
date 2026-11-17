"""Offline, hypothetical security mathematics and defensive investigation lessons.

Original explanations link primary references. The lab has no fetch, storage,
model, detector or host-action integration; its inputs never become policy.
"""

SECURITY_LAB_HTML = '''
<section class="security-lab" aria-labelledby="security-lab-title">
 <header><p class="eyebrow">EXPLORE / SECURITY SCIENCE</p><h3 id="security-lab-title" data-security-lab="v1" tabindex="-1">Why an alert needs evidence</h3><p>Try a worked example. Change the labelled outcomes and see how the mathematics changes. These are hypothetical cases, not measurements of your PC or MEGALODON.</p></header>
 <div class="security-lab-presets" role="group" aria-label="Worked examples"><button type="button" data-lab-example="rare">Rare condition</button><button type="button" data-lab-example="common">More common condition</button><button type="button" data-lab-example="small">Only one alert</button></div>
 <p id="security-lab-example">Rare condition: 100 of 100,000 hypothetical cases contain the condition. The detector catches 90%; 1% of ordinary cases alert.</p>
 <fieldset><legend>Hypothetical outcomes · one decision per independently labelled case</legend><div class="security-lab-inputs">
 <label for="security-lab-tp">True positives (TP)<small>Condition present; alert raised</small><input id="security-lab-tp" inputmode="numeric" type="text" value="90" maxlength="10" pattern="0|[1-9][0-9]{0,9}" autocomplete="off"></label>
 <label for="security-lab-fp">False positives (FP)<small>Condition absent; alert raised</small><input id="security-lab-fp" inputmode="numeric" type="text" value="999" maxlength="10" pattern="0|[1-9][0-9]{0,9}" autocomplete="off"></label>
 <label for="security-lab-fn">False negatives (FN)<small>Condition present; no alert</small><input id="security-lab-fn" inputmode="numeric" type="text" value="10" maxlength="10" pattern="0|[1-9][0-9]{0,9}" autocomplete="off"></label>
 <label for="security-lab-tn">True negatives (TN)<small>Condition absent; no alert</small><input id="security-lab-tn" inputmode="numeric" type="text" value="98901" maxlength="10" pattern="0|[1-9][0-9]{0,9}" autocomplete="off"></label>
 </div><p id="security-lab-input-help">Use whole numbers from 0 to 1,000,000,000. Keep the case definition, label process and selection period the same across all four cells.</p></fieldset>
 <p id="security-lab-status" role="status" aria-live="polite"></p>
 <div id="security-lab-results">
 <p id="security-lab-counts"></p>
 <dl class="security-lab-metrics">
 <div><dt>Precision · how many alerts correspond to the condition?</dt><dd id="security-lab-precision"></dd><small>TP / (TP + FP)</small></div>
 <div><dt>Recall · how many condition-present cases were detected?</dt><dd id="security-lab-recall"></dd><small>TP / (TP + FN)</small></div>
 <div><dt>False-positive rate · how many ordinary cases alert?</dt><dd id="security-lab-fpr"></dd><small>FP / (FP + TN)</small></div>
 <div><dt>Accuracy · fraction of all decisions that agree with labels</dt><dd id="security-lab-accuracy"></dd><small>(TP + TN) / total</small></div>
 </dl>
 <p id="security-lab-interval"></p><p id="security-lab-insight"></p>
 <details><summary>How the uncertainty calculation works</summary><p>For precision, let n = TP + FP, p = TP/n and z = 1.959963984540054. The 95% Wilson interval has center (p + z²/(2n))/(1 + z²/n) and half-width z × √(p(1 − p)/n + z²/(4n²))/(1 + z²/n). Zero alerts leave precision and this interval undefined.</p><p>This interval assumes independent Bernoulli trials with a common success probability and a suitable labelled sample. Repeated packets, overlapping windows, biased labels and changing traffic can violate those assumptions. A confidence interval is not a probability that one actual alert is malicious. These example intervals do not calibrate MEGALODON.</p><p>Precision also follows the base-rate identity s × p₀ / (s × p₀ + f × (1 − p₀)), when its denominator is positive: p₀ is prevalence, s is recall and f is the false-positive rate. Compare the rare and more common examples: recall and false-positive rate stay the same while precision changes.</p></details>
 </div>
 <details class="security-lab-lessons"><summary>Recognize attack patterns and choose the evidence to inspect</summary>
 <article><h4>Repeated service probes</h4><p>Connections to many ports or devices can be discovery, including an authorized inventory job. Compare source, destinations, time window and approved work. A probe does not prove a successful exploit.</p><p><a href="#room-findings-title">Review Findings</a> · <a href="https://attack.mitre.org/techniques/T1046/" target="_blank" rel="noopener noreferrer">MITRE T1046: Network Service Discovery</a></p></article>
 <article><h4>Password guessing and credential reuse</h4><p>Repeated authentication failures can support a brute-force investigation. Check service login logs, account identity, failures followed by success and planned testing. Packet counts alone cannot establish failed logins. Review authentication, MFA and service-specific rate limits; an overly strict account lockout can itself interrupt legitimate users.</p><p><a href="#support-host-security">Review host checks</a> · <a href="https://attack.mitre.org/techniques/T1110/" target="_blank" rel="noopener noreferrer">MITRE T1110: Brute Force</a></p></article>
 <article><h4>Exploits inside an allowed service</h4><p>A firewall exception permits a connection; it does not patch the listening application. Review software versions, application logs, authentication and unexpected process activity. Encryption and a familiar port cannot certify the request as safe.</p><p><a href="#host-protection-title">Review incoming access</a> · <a href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer">MITRE T1190: Exploit Public-Facing Application</a></p></article>
 <article><h4>Scope is mathematics, too</h4><p>An IPv4 /32 names one address; /24 spans 256 addresses; /0 spans all 4,294,967,296 IPv4 addresses. A prefix of p bits spans 2^(32 − p) addresses. IPv6 uses 128 bits, so /128 names one address. Address counts do not prove identity or ownership, and they are not counts of usable hosts. Choose a client range deliberately before adding an exception.</p><p><a href="#host-protection-title">Choose allowed services</a> · <a href="https://www.rfc-editor.org/rfc/rfc4632" target="_blank" rel="noopener noreferrer">RFC 4632: CIDR</a></p></article>
 </details>
 <p class="security-lab-sources">Research: <a href="https://scispace.com/papers/the-base-rate-fallacy-and-the-difficulty-of-intrusion-4td454jjhu" target="_blank" rel="noopener noreferrer">Axelsson: the base-rate fallacy</a> · <a href="https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm" target="_blank" rel="noopener noreferrer">NIST: Wilson intervals</a> · <a href="https://csrc.nist.gov/pubs/sp/800/94/final" target="_blank" rel="noopener noreferrer">NIST: intrusion detection and prevention</a>. Original educational summaries, reviewed November 17, 2026. These links open external sources only when selected.</p>
</section>
'''

SECURITY_LAB_CSS = '''
.help-guide>.security-lab{grid-column:1/-1;border-top:2px solid #5ebcaf;padding-top:24px;min-width:0}
.security-lab header{max-width:90ch}.security-lab h3{font-size:1.4rem}.security-lab p{line-height:1.65;max-width:100ch}.security-lab fieldset{border:1px solid #466775;padding:16px;margin:20px 0;min-width:0}.security-lab legend{padding:0 8px;max-width:100%;line-height:1.5}.security-lab-inputs{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.security-lab label{display:grid;gap:6px}.security-lab small{color:#bbced7;line-height:1.5}.security-lab input{width:100%;box-sizing:border-box;min-width:0;min-height:44px;padding:10px;background:#102b37;border:1px solid #64818e;border-radius:4px;color:#eefaff;font:inherit}.security-lab input[aria-invalid=true]{border-color:#f1bd7b}.security-lab-presets{display:flex;gap:10px;flex-wrap:wrap}.security-lab button{min-height:44px;padding:10px 14px}.security-lab :is(input,button,a,summary):focus-visible{outline:3px solid #a6f4df;outline-offset:3px}.security-lab-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin:20px 0}.security-lab-metrics>div{border-left:3px solid #5ebcaf;padding:12px 16px;background:#0b222c}.security-lab dt{line-height:1.5;color:#c5d8df}.security-lab dd{font-size:1.8rem;font-weight:650;margin:10px 0;color:#d7f6ec;overflow-wrap:anywhere}.security-lab details{border-top:1px solid #375b69;margin-top:18px;padding-top:12px}.security-lab summary{min-height:44px;display:list-item;cursor:pointer;line-height:1.5}.security-lab article{border-top:1px solid #365765;margin-top:16px;padding-top:4px}.security-lab article h4{font-size:1.05rem;margin-bottom:6px}.security-lab a{display:inline-block;padding-block:8px;overflow-wrap:anywhere}.security-lab-sources{font-size:.85rem;color:#bbced7}#security-lab-status{color:#f1cf8b}
@media(max-width:700px){.security-lab-inputs{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:440px){.security-lab-inputs,.security-lab-metrics{grid-template-columns:minmax(0,1fr)}.security-lab fieldset{padding:12px}.security-lab-presets button{flex:1 1 100%}}
'''

SECURITY_LAB_JS = r'''
const MegalodonSecurityMath=(()=>{
 'use strict';
 function ratio(n,d){return d===0?null:n/d;}
 function summarize(c){
   if(!c||Object.keys(c).sort().join(',')!=='fn,fp,tn,tp'||!Object.values(c).every(v=>Number.isSafeInteger(v)&&v>=0&&v<=1000000000))throw Error('Invalid labelled counts.');
   const {tp,fp,fn,tn}=c,total=tp+fp+fn+tn,alerts=tp+fp;
   const precision=ratio(tp,alerts),recall=ratio(tp,tp+fn),fpr=ratio(fp,fp+tn),accuracy=ratio(tp+tn,total);
   let interval=null;
   if(alerts){const z=1.959963984540054,z2=z*z,scale=1+z2/alerts,center=(precision+z2/(2*alerts))/scale,half=z*Math.sqrt(precision*(1-precision)/alerts+z2/(4*alerts*alerts))/scale;interval=[Math.max(0,center-half),Math.min(1,center+half)];}
   return {total,alerts,condition:tp+fn,precision,recall,fpr,accuracy,interval};
 }
 function percent(v){if(v===null)return 'Undefined · no denominator';if(v>0&&v<0.0001)return '<0.01%';if(v<1&&v>0.9999)return '>99.99%';return (100*v).toFixed(2)+'%';}
 return Object.freeze({summarize,percent});
})();
(()=>{
 'use strict';
 if(document.getElementById('security-lab-title')?.getAttribute?.('data-security-lab')!=='v1')return;
 const el=id=>document.getElementById('security-lab-'+id),fields=['tp','fp','fn','tn'];
 const examples={rare:[90,999,10,98901],common:[9000,900,1000,89100],small:[1,0,0,999]};
 const descriptions={rare:'Rare condition: 100 of 100,000 hypothetical cases contain the condition. The detector catches 90%; 1% of ordinary cases alert.',common:'More common condition: 10,000 of 100,000 hypothetical cases contain the condition. Recall stays 90% and the false-positive rate stays 1%.',small:'Only one alert: one true positive and no false positives. One example does not establish reliable precision.'};
 function render(){
   const counts={};let invalid=false;
   for(const key of fields){const input=el(key),raw=input.value,ok=/^(0|[1-9][0-9]{0,9})$/.test(raw)&&Number(raw)<=1000000000;input.setAttribute('aria-invalid',String(!ok));input.setAttribute('aria-describedby','security-lab-input-help security-lab-status');if(ok)counts[key]=Number(raw);else invalid=true;}
   el('results').hidden=invalid;
   if(invalid){el('status').textContent='Complete all four counts with whole numbers from 0 to 1,000,000,000. Previous results are hidden.';return;}
   const value=MegalodonSecurityMath.summarize(counts),quantity=(n,word)=>`${n.toLocaleString()} ${word}${n===1?'':'s'}`;
   el('status').textContent=`Hypothetical precision: ${MegalodonSecurityMath.percent(value.precision)}. Recall: ${MegalodonSecurityMath.percent(value.recall)}.`;
   for(const key of ['precision','recall','fpr','accuracy'])el(key).textContent=MegalodonSecurityMath.percent(value[key]);
   el('counts').textContent=`${quantity(value.total,'hypothetical case')} · ${value.condition.toLocaleString()} condition-present · ${quantity(value.alerts,'alert')}. Missing labels cannot be counted as ordinary cases.`;
   el('interval').textContent=value.interval?`Hypothetical 95% Wilson interval for precision: ${MegalodonSecurityMath.percent(value.interval[0])} to ${MegalodonSecurityMath.percent(value.interval[1])}. Read the sampling assumptions below.`:'Precision and its Wilson interval are undefined because there are no alerts.';
   el('insight').textContent=value.total===0?'No hypothetical cases supplied. Undefined is different from zero or perfect performance.':`This labelled example raises ${quantity(value.alerts,'alert')}, including ${quantity(counts.fp,'false positive')}. Accuracy alone can hide the review workload. These figures never change a detector or authorize blocking.`;
 }
 for(const key of fields)el(key).addEventListener('input',()=>{el('example').textContent='Custom hypothetical counts. Their labels and sampling assumptions are supplied by you.';render();});
 document.querySelectorAll('[data-lab-example]').forEach(button=>button.addEventListener('click',()=>{const name=button.getAttribute('data-lab-example');fields.forEach((key,i)=>{el(key).value=String(examples[name][i]);});el('example').textContent=descriptions[name];render();}));
 render();
})();
'''
