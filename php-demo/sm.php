<?php

function get_sm_script_path() {
	return dirname(__FILE__).'/sm';
}

function check_sm_executable() {
	$path = get_sm_script_path();
	if (!file_exists($path) || !is_executable($path)) {
		throw new Exception("{$path} not exist or not executable", '999');
	}
}
/**
 * sm2对称加密
 *
 * @param  string $str    待加密的字符串
 * @param  string $pubKey 公钥，已转换为字符串
 *
 * @return [string]       返回的密串
 */
function sm2Encrypt($str = '', $pubKey = '') {
	check_sm_executable();
	exec(get_sm_script_path().' -smType sm2Encrypt -str '.$str.' -pubKey '.$pubKey, $res, $isSuccess);
	if ($isSuccess !== 0 || empty($res[0])) {
		return '';
	}

	return $res[0];
}


/**
 * sm2对称解密
 *
 * @param  string $str    密串
 * @param  string $privKey 私钥，已转换为字符串
 *
 * @return [string]       返回的解密内容
 */
function sm2Decrypt($str = '', $privKey = '') {
	check_sm_executable();
	exec(get_sm_script_path().' -smType sm2Decrypt -str '.$str.' -privKey '.$privKey, $res, $isSuccess);
	if ($isSuccess !== 0 || empty($res[0])) {
		return '';
	}

	return $res[0];
}


/**
 * sm4对称加密
 *
 * @param  string $str    待加密的字符串
 * @param  string $pubKey 私钥，已转换为字符串
 *
 * @return [string]       返回的密串
 */
function sm4Encrypt($str = '', $sm4PrivKey = '', $sm4IV = '') {
	check_sm_executable();
	exec(get_sm_script_path().' -smType sm4Encrypt -str '.$str.' -sm4PrivKey '.$sm4PrivKey.' -sm4IV '.$sm4IV, $res, $isSuccess);
	if ($isSuccess !== 0 || empty($res[0])) {
		return '';
	}

	return $res[0];
}


/**
 * sm4对称解密
 *
 * @param  string $str    密串
 * @param  string $pubKey 私钥，已转换为字符串
 *
 * @return [string]       返回字符串
 */
function sm4Decrypt($str = '', $sm4PrivKey = '', $sm4IV = '') {
	check_sm_executable();
	exec(get_sm_script_path().' -smType sm4Decrypt -str '.$str.' -sm4PrivKey '.$sm4PrivKey.' -sm4IV '.$sm4IV, $res, $isSuccess);
	if ($isSuccess !== 0 || empty($res[0])) {
		return '';
	}

	return $res[0];
}


/**
 * sm3字符串、文件流的hash
 *
 * @param  string $str    字符串、文件流
 *
 * @return [string]       返回hash
 */
function sm3Hash($str = '') {
	check_sm_executable();
	exec(get_sm_script_path().' -smType sm3Hash -str '.$str, $res, $isSuccess);
	if ($isSuccess !== 0 || empty($res[0])) {
		return '';
	}

	return $res[0];
}

// demo1：sm2 加密
$res1 = sm2Encrypt('abc', '04fc8e60b7974965284ce76e319ea0295b5f785f433069b68343d0f8453a63ba8e31734373bb59dc31f7806fc69d060eb91ad32810bd280901372f327510521937');

// demo2：sm2 解密
$res2 = sm2Decrypt('306b022063d6ced4dfc7bc2b2f80a5570293640f5b30fe4637791b3bffa502d5e730492a022073e9bf9e744056dfec56b37c05c42befbf6c2825d18e6ce1a55e78974670d7210420dac89cf4b4000612cdcc66272e0d117b33b7b95e3d47b279332aecf4ba891aa104032d0304', 'ddae96473a756fcb3ec3eab140ad3b1005ba54a9a2817b0940d2f37ded2c4451');

// demo3：sm4 加密
$res3 = sm4Encrypt('abc', '524d69faaa0eb268', 'dcac050c27357873');

// demo4：sm4 解密
$res4 = sm4Decrypt('f96d3eabb098b072d86f101c83399076', '524d69faaa0eb268', 'dcac050c27357873');

// demo5：sm3 hash
$res5 = sm3Hash('123456');

var_dump($res1);
var_dump($res2);
var_dump($res3);
var_dump($res4);
var_dump($res5);