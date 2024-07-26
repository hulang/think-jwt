**ThinkPHP 8.0+ Jwt**

基于`firebase/php-jwt ^6.10`的`ThinkPHP 8.0+ Jwt 验证`

<p align="center"> 
  您是第  <img src="https://profile-counter.glitch.me/github:hulang:think-jwt/count.svg" />位访问者
</p>

#### 安装 

```sh
composer require hulang/think-jwt
```

#### 环境要求

- php >= 8.0
- thinkphp >= 8.0

#### 配置

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
#### 使用案例
```php
/**
 * ThinkPHP 8.0+ Jwt 验证
 * @see \think\facade\Jwt
 * @package think\facade\Jwt
 * @mixin \think\facade\Jwt
 * @method static mixed|string|Exception getToken($data = []) 获取token
 * @method static mixed|array Check($token = '') 验证令牌(Token)的有效性
 * @method static mixed|array Refresh($token = '') 刷新令牌
 * @method static mixed|array Logout($token = '') 注销令牌
 * @method static mixed|array|Exception Parse($token = '', $type = 0) 解析并验证JWT令牌
 */
```

#### controller

```php
<?php
namespace app\index\controller;

use think\facade\Jwt;

class McjController {

    // 获取token,data为用户自定义数据
    public function create()
    {
        $data = [
            'user_id' => 12
        ];
        $res = '';
        try {
            $res = Jwt::getToken($data);
            print_r($res);
            exit;
        } catch (\Exception $e) {
            echo json_encode(['error_msg' => $e->getMessage()]);
        }
        print_r($res);
        exit;
    }

    // 权限认证
    public function check()
    {
        $res = '';
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImFIZk1VTjRhanFDZnZEOGIifQ.eyJuYmYiOjE3MjE5NTc4MDQsImV4cCI6MTcyMjU2MjYwNCwiand0X2lkZSI6ImFIZk1VTjRhanFDZnZEOGIiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.RobEm_KWVEkKsjpK5EAvib82Y7rsnGHLhXrKfhEFcDQ';
        try {
            $res = Jwt::Check($token);
        } catch (\Exception $e) {
            echo json_encode(['error_msg' => $e->getMessage()]);
        }
        print_r($res);
        exit;
    }

    // 权限认证
    public function parse()
    {
        $res = '';
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImFIZk1VTjRhanFDZnZEOGIifQ.eyJuYmYiOjE3MjE5NTc4MDQsImV4cCI6MTcyMjU2MjYwNCwiand0X2lkZSI6ImFIZk1VTjRhanFDZnZEOGIiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.RobEm_KWVEkKsjpK5EAvib82Y7rsnGHLhXrKfhEFcDQ';
        try {
            $res = Jwt::Parse($token, 1);
        } catch (\Exception $e) {
            echo json_encode(['error_msg' => $e->getMessage()]);
        }
        print_r($res);
        exit;
    }

    // 刷新令牌
    public function refresh()
    {
        $res = '';
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImFIZk1VTjRhanFDZnZEOGIifQ.eyJuYmYiOjE3MjE5NTc4MDQsImV4cCI6MTcyMjU2MjYwNCwiand0X2lkZSI6ImFIZk1VTjRhanFDZnZEOGIiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.RobEm_KWVEkKsjpK5EAvib82Y7rsnGHLhXrKfhEFcDQ';
        try {
            $res = Jwt::Refresh($token);
        } catch (\Exception $e) {
            echo json_encode(['error_msg' => $e->getMessage()]);
        }
        print_r($res);
        exit;
    }

    // 注销令牌,账号登出
    public function logout()
    {
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImFIZk1VTjRhanFDZnZEOGIifQ.eyJuYmYiOjE3MjE5NTc4MDQsImV4cCI6MTcyMjU2MjYwNCwiand0X2lkZSI6ImFIZk1VTjRhanFDZnZEOGIiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.RobEm_KWVEkKsjpK5EAvib82Y7rsnGHLhXrKfhEFcDQ';
        try {
            Jwt::Logout($token);
        } catch (\Exception $e) {
            echo json_encode(['error_msg' => $e->getMessage()]);
        }
        echo ('logout success');
    }

}
```
