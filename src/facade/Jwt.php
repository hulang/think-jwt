<?php

declare(strict_types=1);

namespace think\facade;

use think\Facade;

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
 * @method static mixed|string getRequestToken() 获取请求头HTTP_AUTHORIZATION字段的token值
 */
class Jwt extends Facade
{
    protected static function getFacadeClass()
    {
        return \think\Jwt::class;
    }
}
