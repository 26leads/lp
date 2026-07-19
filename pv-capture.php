<?php
/** Capture lead photovoltaïque → injection dans La Bourse du Lead (produit pv). */
$BOURSE_API   = 'https://boursedulead.com/api/import_lead.php';
require __DIR__ . '/.secret_token.php'; // définit IMPORT_TOKEN (hors dépôt)
$IMPORT_TOKEN = IMPORT_TOKEN;
$CONSENT_TEXT = "J'accepte d'être recontacté(e) par un installateur partenaire par téléphone, e-mail ou SMS au sujet de mon projet solaire.";
$LOG_CONSENT  = '/var/log/bdl_consent/pv.jsonl';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: /'); exit; }
if (!empty($_POST['website'])) { header('Location: /merci.html'); exit; }

function clean($k){ return isset($_POST[$k]) ? trim(strip_tags($_POST[$k])) : ''; }
$prenom=clean('prenom'); $nom=clean('nom');
$tel=preg_replace('/[^0-9+]/','',clean('telephone'));
$email=filter_var(clean('email'),FILTER_SANITIZE_EMAIL);
$cp=preg_replace('/[^0-9]/','',clean('code_postal'));
$logement=clean('type_logement'); $orient=clean('orientation'); $surf=clean('surface_toit'); $fact=clean('facture');
$consent=isset($_POST['consent']);

$errors=[];
if($consent!==true) $errors[]='consent';
if(strlen($tel)<9) $errors[]='telephone';
if(!filter_var($email,FILTER_VALIDATE_EMAIL)) $errors[]='email';
if(strlen($cp)!==5) $errors[]='code_postal';
if($nom===''||$prenom==='') $errors[]='nom';
if($errors){ header('Location: /?erreur='.implode(',',$errors)); exit; }

$departement=substr($cp,0,2);
$now=new DateTime('now',new DateTimeZone('Europe/Paris'));
$proof=[
  'timestamp'=>$now->format('c'),'ip'=>$_SERVER['REMOTE_ADDR']??'','ua'=>$_SERVER['HTTP_USER_AGENT']??'',
  'source'=>clean('source')?:($_SERVER['HTTP_HOST']??''),
  'url'=>'https://'.($_SERVER['HTTP_HOST']??'').($_SERVER['REQUEST_URI']??''),
  'consent_text'=>$CONSENT_TEXT,'lead'=>['nom'=>$nom,'prenom'=>$prenom,'tel'=>$tel,'email'=>$email,'cp'=>$cp],
];
$proof['hash']=hash('sha256',json_encode($proof).$IMPORT_TOKEN);
@mkdir(dirname($LOG_CONSENT),0750,true);
@file_put_contents($LOG_CONSENT,json_encode($proof,JSON_UNESCAPED_UNICODE)."\n",FILE_APPEND|LOCK_EX);

$details='Projet photovoltaïque — orientation: '.$orient.' — surface toit: '.$surf.' — facture: '.$fact.' — consentement scellé '.$proof['hash'];
$payload=[
  'telephone'=>$tel,'produit'=>'pv','nom'=>$nom,'prenom'=>$prenom,'email'=>$email,
  'code_postal'=>$cp,'departement'=>$departement,'type_logement'=>$logement,
  'qualite'=>'Exclusif','details'=>$details,
];
$ch=curl_init($BOURSE_API);
curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE),
  CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-Api-Token: '.$IMPORT_TOKEN],
  CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10]);
$resp=curl_exec($ch); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
@file_put_contents('/var/log/bdl_consent/pv_api.log',$now->format('c')." http=$code resp=".substr((string)$resp,0,200)."\n",FILE_APPEND);

header('Location: /merci.html'); exit;
