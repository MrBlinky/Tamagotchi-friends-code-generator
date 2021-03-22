<?php
$passwordchars1  = array('0' ,'1' ,'2' ,'3' ,'4' ,'5' ,'6' ,'7' ,'8' ,'9', 'A' ,'B' ,'C' ,'D' ,'E' ,'F'); #for 1st 6 digits
$passwordchars2  = array('A' ,'B' ,'C' ,'D' ,'E' ,'F' ,'G' ,'H' ,'I' ,'J' ,'K' ,'L' ,'M' ,'N' ,'O' ,'P' ,'Q' ,'R' ,'S' ,'T' ,'U' ,'V' ,'W' ,'X' ,'Y' ,'Z','0'); #for 7th digit and on
$namechars       = array('A' ,'B' ,'C' ,'D' ,'E' ,'F' ,'G' ,'H' ,'I' ,'J' ,'K' ,'L' ,'M' ,'N' ,'O' ,'P' ,'Q' ,'R' ,'S' ,'T' ,'U' ,'V' ,'W' ,'X' ,'Y' ,'Z',' '); #for display name only
$namechars_xor   = array(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xA0);
$checksum_xor    = array(0x11, 0x32, 0x53, 0x74, 0x15, 0x36, 0x58, 0x77, 0x29, 0x4F, 0x6E, 0x0D, 0x2C, 0x4B, 0x6A, 0x7F);
$step3count_xor  = array(0x57, 0x3A);
$nameorder       = array(6, 8, 10, 7, 9, 13, 11, 12); #digit order of name characters
$step13count_add = array ([1, 2, 3, 4, 5, 6, 7, 8],
						 [2, 3, 4, 5, 6, 7, 8, 1],
						 [3, 4, 5, 6, 7, 8, 1, 2],
						 [4, 5, 6, 7, 8, 1, 2, 3], 
						 [5, 6, 7, 8, 1, 2, 3, 4], 
						 [6, 7, 8, 1, 2, 3, 4, 5],
						 [7, 2, 1, 2, 3, 4, 5, 6],
						 [8, 1, 2, 3, 4, 5, 6, 7]);
						 
if (isset($_GET['code1']) and isset ($_GET['code2'])) $login = strtoupper($_GET['code1'] . $_GET['code2']); else $login ='';
if (isset($_GET['type'])) $type = $_GET["type"]; else $type = 0;
if (isset($_GET['item'])) $item = $_GET["item"]; else $item = 0;

$error = 0;				   
$code1='0000';
$code2='0000';

#check login code input
If (strlen($login) != 14)  {
	$error = 1;
} else {
	for ($i = 0; $i <6; $i++) {
		if (!in_array($login[$i],$passwordchars1)) {
			$error = 1;
			break;
		}
	}
	for ($i = 6; $i <14; $i++) {
		if (!in_array($login[$i],$passwordchars2)) {
			$error = 1;
			break;
		}
	}
}
#check item input
if ($type < 0) $type = 0; else if ($type > 5) $type = 5;
if ($item < 0) $item = 0;
if ($type == 0) {
	if ($item > 29) $item = 29;
} else if ($type == 1) {
	if ($item > 29) $item = 29;
	$item += 30;
} else {
	if ($item > 14) $item = 14;
	$item += ($type-2) * 15;
	$type = 2;
}

#decode and validate login password
if (!$error) { 
	$checksum    = array_search($login[0],$passwordchars1);
	$step13count = array_search($login[1],$passwordchars1) >> 1;
	$step3count  = array_search($login[1],$passwordchars1) &  1;
	$name ='';
	for ($i = 0; $i < 8; $i ++) {#get user name
		$c = array_search($login[$nameorder[$i]],$passwordchars2) - $step13count_add[$step13count][$i];
		if ($c < 0) $c += 0x1B;
		$name .= $namechars[$c];
	}
	$logindata = array ( #login data for decoding and checksum verifying
				(array_search($login[4],$passwordchars1) << 4)   | array_search($login[5],$passwordchars1), # ^  $step3count_xor[$step3count] ^ $namechars_xor[array_search($name[1],$namechars)] ^ $checksum_xor[$checksum],
				(array_search($login[2],$passwordchars1) << 4)   | array_search($login[3],$passwordchars1), # ^  $step3count_xor[$step3count] ^ $namechars_xor[array_search($name[3],$namechars)] ^ $checksum_xor[$checksum],
				((array_search($name[1],$namechars) & 0x3) << 6) |  array_search($name[0],$namechars),
				((array_search($name[2],$namechars) & 0xF) << 4) | (array_search($name[1],$namechars) >> 2),
				(array_search($name[3],$namechars) << 2)         | (array_search($name[2],$namechars) >> 4),
				((array_search($name[5],$namechars) & 0x3) << 6) |  array_search($name[4],$namechars),
				((array_search($name[6],$namechars) & 0xF) << 4) | (array_search($name[5],$namechars) >> 2),
				(array_search($name[7],$namechars) << 2)         | (array_search($name[6],$namechars) >> 4),
				(array_search($login[0],$passwordchars1) << 4)   | array_search($login[1],$passwordchars1)
				);
	#step 3 counter xoring			   
	$logindata[0] ^= $step3count_xor[$step3count];
	$logindata[1] ^= $step3count_xor[$step3count];
	#name xoring
	$logindata[0] ^= $namechars_xor[array_search($name[1],$namechars)];
	$logindata[1] ^= $namechars_xor[array_search($name[3],$namechars)];
	#checksum xoring
	$logindata[0] ^= $checksum_xor[$checksum];
	$logindata[1] ^= $checksum_xor[$checksum];
	#verify checksum
	$c = 0;
	for ($i = 0; $i < 17; $i++) {
		if (($i & 1) == 1) {
			$c -= ($logindata[$i >> 1] >> 4);
		} else {
			$c -= ($logindata[$i >> 1] & 0xF);
		}
	}
	if (($c & 0xF) != $checksum) $error = 1;
}
#create logout password
if (!$error) {
	#unique tamagotchi data
	$tama_id    = $logindata[0] &  0x3F;
	$step7count = $logindata[1] >> 4;
	$device_id  = ($logindata[0] >> 6) | (($logindata[1] & 0xF) << 2);
	
	#create logout data	                                           
	$logoutdata = array( 
	            $logindata[0],                                    
				$logindata[1] | 0x80,                             
				$item,                           
				($step3count << 3) | $type
				);
	$checksum = (0 - ($logoutdata[1] >> 4) - ($logoutdata[1] & 0xF) -
					 ($logoutdata[0] >> 4) - ($logoutdata[0] & 0xF) -
					 ($logoutdata[2] >> 4) - ($logoutdata[2] & 0xF) -
					 ($logoutdata[3] & 0xF)) & 0XF;
	#checksum xoring	
	for ($i = 0; $i < 3; $i++) {
		$logoutdata[$i] ^= $checksum_xor[$checksum];
	}
	#player name xoring	
	$logoutdata[0] ^= $namechars_xor[array_search($name[1],$namechars)];
	$logoutdata[1] ^= $namechars_xor[array_search($name[3],$namechars)];
	$logoutdata[2] ^= $namechars_xor[array_search($name[5],$namechars)];
	#step 3 counter xoring	
	for ($i = 0; $i < 3; $i++) {
		$logoutdata[$i] ^= $step3count_xor[$step3count];
	}
	#create code strings
	$code1 = sprintf('%X%X%X%X',
	$logoutdata[1] >> 4, $logoutdata[1] & 0xF,
	$logoutdata[0] >> 4, $logoutdata[0] & 0xF
	);
	$code2 = sprintf('%X%X%X%X',
	$checksum          , $logoutdata[3] & 0xF,
	$logoutdata[2] >> 4, $logoutdata[2] & 0xF
	);
}
?>
<html lang="en"><head><meta charset="UTF-8"><title>Tamagotchi Friends EZgotchi - code generator</title><link rel="manifest" href="manifest.json"><head><style>
.codeok {position:relative;top:90px;height:150px}
.coderr {position:relative;left:12px;top:140px;width:450px;text-align:left}
.logout {display:block; background-color:rgba(255, 255, 255, 0.5); border: 3px solid black;border-radius: 16px;width:300px;position:relative;margin:8px;padding:4px;font-size:56px;text-align: center}
.submit {display:block; background-color:rgba(255, 255, 255, 0.5); border: 3px solid black;border-radius: 80px;left:250px;top:520px;width:500px;height:160px;position:absolute;margin:8px;padding:4px;font-size:48px;text-align: center}
</style></head><body><center>
<div style="background-repeat: no-repeat;background-image:url(pink-hearts.jpg);background-size:100%; width:1024px;height:1200px; position:relative;">
<div style="position:relative;left: 4px;top: 330px;font-family:arial;font-weight:bold;font-size:48px;line-height:48px">
<?php
if ($error==1) echo '<div class="coderr">Invalid login code. Please check your Tamagotchi screen again.</div>';
else echo '<div class="codeok">Logout code:</div><div class="logout">' . $code1 . '</div><div class="logout">' . $code2 . '</div>';
?>
<form action="./"><input type="submit" value="BACK" class="submit"></form>
</div></div></center></body></html>
