# thinkphp-jwt

## 安装 
使用composer管理依赖方式安装
```
composer require hulang/think-jwt
```

## 环境要求

php:>=8.0
thinkphp:>=8.0

## 配置

```php
<?php

declare(strict_types=1);

// +----------------------------------------------------------------------
// | 配置
// +----------------------------------------------------------------------

return [
    // 加密秘钥
    'secret' => env('JWT_SECRET'),
    // 过期时间,单位秒 默认 10 小时
    'exp' => (60 * 60) * 10,
    // 刷新时间,单位秒 默认 7 天
    'refresh' => ((60 * 60) * 24) * 7,
];

```
## 使用案例
```php
<?php
namespace app\index\controller;

use think\facade\Jwt;

class McjController {

    // 获取token,data为用户自定义数据
    public function create(){
        $data = [
            'user_id'=>12
        ];
        try{
            $res = Jwt::getToken($data);
        }catch (\Exception $e){
            echo json_encode(['error_msg'=>'加密出错']);
        }
        dump($res);exit;
    }
    // 权限认证
    public function check(){
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlFzMkdJaVRnVldSVUZSV3MifQ.eyJuYmYiOjE1MzQyMzQyNDksImV4cCI6MTUzNDgzOTA0OSwiand0X2lkZSI6IlFzMkdJaVRnVldSVUZSV3MiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.pond6EJ59yH9k3MJusVugg7W6hHx1Y_lLGawJBctflY';
        try{
            $res =  Jwt::Check($token);
        }catch (\Exception $e){
            //token暂时失效，请刷新令牌
            if($e->getCode() === 20001){
                echo json_encode(['error_msg'=>'请刷新token']);
            }else{
                echo json_encode(['error_msg'=>'登录过期，请重新登录']);
            }
        }
        dump($res);
    }

    // 刷新令牌
    public function refresh(){
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlFzMkdJaVRnVldSVUZSV3MifQ.eyJuYmYiOjE1MzQyMzQyNDksImV4cCI6MTUzNDgzOTA0OSwiand0X2lkZSI6IlFzMkdJaVRnVldSVUZSV3MiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.pond6EJ59yH9k3MJusVugg7W6hHx1Y_lLGawJBctflY';
        try{
            $res =  Jwt::Refresh($token);
        }catch (\Exception $e){
            echo json_encode(['error_msg'=>'token不合法']);
        }
        dump($res);
    }
    // 注销令牌,账号登出
    public function logout(){
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlFzMkdJaVRnVldSVUZSV3MifQ.eyJuYmYiOjE1MzQyMzQyNDksImV4cCI6MTUzNDgzOTA0OSwiand0X2lkZSI6IlFzMkdJaVRnVldSVUZSV3MiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.pond6EJ59yH9k3MJusVugg7W6hHx1Y_lLGawJBctflY';
        try{
            Jwt::Logout($token);
        }catch (Exception $e){
            echo json_encode(['error_msg'=>'token不合法']);
        }
        echo('logout success');
    }

}
```