**ThinkPHP 8.0+ Jwt**

基于`firebase/php-jwt ^7.2`的`ThinkPHP 8.0+ JWT 验证`，内置路由中间件

<p align="center"> 
  您是第  <img src="https://profile-counter.glitch.me/github:hulang:think-jwt/count.svg" />位访问者
</p>

#### 安装 

```sh
composer require hulang/think-jwt
```

#### 环境要求

- php >= 8.2
- thinkphp >= 8.0
- firebase/php-jwt ^7.2

#### 配置

```php
<?php

declare(strict_types=1);

// +----------------------------------------------------------------------
// | 配置
// +----------------------------------------------------------------------

return [
    // 加密秘钥,上线务必改掉并放在 .env 里
    // 写短字符串也能用:类初始化时会把 secret 统一做一次 SHA-256 派生,转成 32 字节密钥,
    // 满足 firebase/php-jwt 7.x 对 HS256 的长度要求
    'secret' => '20240726@hulang',

    // 过期时间,单位秒 默认 10 小时
    // 含义是“签发后多久要求刷新”:到点后 Check() 返回 code=0、errno=20001,
    // 前端拿旧 token 调 Refresh() 换新 token;token 本身要到 refresh 才真正失效
    'exp' => (60 * 60) * 10,

    // 刷新时间,单位秒 默认 7 天(token 的实际有效期,对应 payload 里的 exp)
    'refresh' => ((60 * 60) * 24) * 7,

    // 中间件放行白名单,支持 * 通配,例如 ['api/login', 'api/register', 'api/captcha/*']
    'except' => [],

    // 中间件默认是否允许匿名访问:
    // false 表示没 token 直接 401;true 表示没 token 也放行,由控制器自行判断是否登录
    'optional' => false,
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
 * @method static mixed|string getRequestHeaders() 获取请求头中的Authorization字段,用于提取token
 * @method static mixed|string getRequestToken($request) 从请求中获取授权令牌
 * @method static mixed|string getFromAltHeaders(Request $request) 从请求的备用头部中获取认证信息
 */
```

`Check()` 的返回结构固定是 `code / msg / data / errno`：

- `code`：1 通过，0 失败
- `msg`：失败原因
- `data`：通过时是业务数据
- `errno`：失败时的业务错误码，方便前端区分“过期”与“非法”

#### 中间件

中间件类：`\think\middleware\JwtAuth`，校验通过后会把业务数据挂到 `$request->jwtData`。

```php
// 1. 单个路由
Route::get('user/info', 'User/info')->middleware(\think\middleware\JwtAuth::class);

// 2. 整组路由
Route::group('api', function () {
    Route::get('user/info', 'User/info');
    Route::post('user/update', 'User/update');
})->middleware(\think\middleware\JwtAuth::class);

// 3. 允许匿名访问(没 token 也放行,控制器里自行判断是否登录)
Route::get('article/detail', 'Article/detail')
    ->middleware(\think\middleware\JwtAuth::class . ':true');
```

全局注册 + 白名单（`config/jwt.php` 的 `except` 支持 `*` 通配）：

```php
// app/middleware.php
return [
    \think\middleware\JwtAuth::class,
];
```

```php
// config/jwt.php
'except' => ['api/login', 'api/register', 'api/captcha/*'],
```

控制器里取当前登录用户的数据：

```php
<?php
namespace app\index\controller;

use think\Request;

class User
{
    // 中间件校验通过后,jwtData 就是签发时 getToken() 里传的 data
    public function info(Request $request)
    {
        $userId = $request->jwtData['user_id'] ?? 0;
        return json(['code' => 1, 'msg' => 'ok', 'data' => ['user_id' => $userId]]);
    }
}
```

#### 错误码

| 常量 | 值 | 含义 |
|---|---|---|
| `INVALID_TOKEN` | 40001 | token 格式不合法、签名无效、尚未生效 |
| `TOKEN_EMPTY` | 40002 | 请求没有携带 token |
| `TOKEN_EXPIRE` | 20001 | 签发超过 exp，需要刷新 |
| `TOKEN_EXPIRE_LONG` | 20002 | token 已过期（超过 refresh） |
| `TOKEN_LOGOUT` | 20003 | token 已被注销 |
| `TOKEN_DOMAIN` | 20004 | 签名算法或密钥不匹配 |
| `ENCRYPT_EORROR` | 50001 | 加密运算异常 |
| `JWT_SECRET_MISS` | 50002 | 秘钥未设置 |

#### 从旧版本升级注意

1. 旧版本用 `firebase/php-jwt 6.x`，7.x 对 HS256 有 32 字节密钥长度校验，本版本已用 `deriveKey()` 自动派生补齐。
2. 如果原来配置的是短 secret，升级后实际参与签名的密钥已经变化，**已签发的旧 token 会全部失效，用户需要重新登录**。
3. 生产环境建议直接配置 32 字节以上的随机串，派生只是补长度，不增加真实强度。
4. 建议升级后先跑一遍登录、刷新、注销三条链路再上线。

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
        try {
            $res = Jwt::getToken($data);
            print_r($res);
            exit;
        } catch (\Exception $e) {
            echo json_encode(['error_msg' => $e->getMessage()]);
        }
        exit;
    }

    // 权限认证
    public function check()
    {
        $token = '把上一步拿到的 token 放这里';
        $res = Jwt::Check($token);
        print_r($res);
        exit;
    }

    // 解析令牌,返回完整载荷
    public function parse()
    {
        $token = '把上一步拿到的 token 放这里';
        $res = Jwt::Parse($token, 1);
        print_r($res);
        exit;
    }

    // 刷新令牌
    public function refresh()
    {
        $token = '把上一步拿到的 token 放这里';
        $res = Jwt::Refresh($token);
        print_r($res);
        exit;
    }

    // 注销令牌,账号登出
    public function logout()
    {
        $token = '把上一步拿到的 token 放这里';
        $res = Jwt::Logout($token);
        print_r($res);
        exit;
    }

}
```
