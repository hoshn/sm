### GO+PHP 实现sm2/sm3/sm4加密

#### PHP封装调用Go的二进制包
````
// demo1：sm2 非对称加密
$res1 = sm2Encrypt('abc', '04fc8e60b7974965284ce76e319ea0295b5f785f433069b68343d0f8453a63ba8e31734373bb59dc31f7806fc69d060eb91ad32810bd280901372f327510521937');
````
````
// demo2：sm2 非对称解密
$res2 = sm2Decrypt('306b022063d6ced4dfc7bc2b2f80a5570293640f5b30fe4637791b3bffa502d5e730492a022073e9bf9e744056dfec56b37c05c42befbf6c2825d18e6ce1a55e78974670d7210420dac89cf4b4000612cdcc66272e0d117b33b7b95e3d47b279332aecf4ba891aa104032d0304', 'ddae96473a756fcb3ec3eab140ad3b1005ba54a9a2817b0940d2f37ded2c4451');
````
````
// demo3：sm4 对称加密
$res3 = sm4Encrypt('abc', '524d69faaa0eb268', 'dcac050c27357873');
````
````
// demo4：sm4 对称解密
$res4 = sm4Decrypt('f96d3eabb098b072d86f101c83399076', '524d69faaa0eb268', 'dcac050c27357873');
````
````
// demo5：sm3 hash
$res5 = sm3Hash('123456');

````
