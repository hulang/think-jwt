<?php

declare(strict_types=1);

namespace think\facade;

use think\Facade;

/**
 * ThinkPHP Jwt Facade
 * @see \think\facade\Jwt
 * @package think\facade\Jwt
 * @mixin \think\facade\Jwt
 * @method static mixed|string getToken($data = []) 获取token
 * @method static mixed|array Check($token = '') 验证令牌(Token)的有效性
 * @method static mixed|string Refresh($token = '') 刷新令牌
 * @method static mixed|bool Logout($token) 注销令牌
 * @method static mixed|array|Exception Parse($token) 解析并验证JWT令牌
 */
class Jwt extends Facade
{
    protected static function getFacadeClass()
    {
        return \think\Jwt::class;
    }
}
