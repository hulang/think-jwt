<?php

declare(strict_types=1);

namespace think\middleware;

use Closure;
use think\Jwt;
use think\Request;
use think\Response;

/**
 * Jwt 认证中间件(ThinkPHP 8.0+)
 *
 * 作用:在进入控制器之前取 Authorization 头里的 token 并校验,
 * 校验通过后把业务数据挂到 $request->jwtData,控制器直接取用;
 * 校验失败直接返回 401 JSON,不再往下走。
 *
 * 用法一,路由里逐个加:
 *   Route::get('user/info', 'User/info')->middleware(\think\middleware\JwtAuth::class);
 *
 * 用法二,给整组路由加:
 *   Route::group('api', function () {
 *       // 这里的路由都需要 token
 *   })->middleware(\think\middleware\JwtAuth::class);
 *
 * 用法三,允许匿名访问(没有 token 也放行,控制器自行判断是否登录):
 *   ->middleware(\think\middleware\JwtAuth::class . ':true')
 *
 * 用法四,在 app/middleware.php 里全局注册,再配合 config/jwt.php 的 except 白名单:
 *   return [ \think\middleware\JwtAuth::class ];
 *
 * @package think\middleware\JwtAuth
 */
class JwtAuth
{
    /**
     * 中间件入口
     *
     * @param Request $request 当前请求对象
     * @param Closure $next 下一步回调
     * @param mixed $optional 是否允许匿名访问,支持 true/false/1/0/字符串,不传时读 config('jwt.optional')
     * @return Response
     * @throws \Exception 生成 Jwt 实例失败时抛出
     */
    public function handle(Request $request, Closure $next, $optional = false): Response
    {
        // 1. 命中白名单的路径直接放行,例如登录、注册、验证码接口
        if ($this->inExcept($request) === true) {
            return $next($request);
        }

        // 2. 从请求头取 token
        /** @var Jwt $jwt */
        $jwt = app(Jwt::class);
        $token = $jwt->getRequestToken($request);

        // 3. 没有携带 token
        if ($token === '') {
            if ($this->isOptional($optional) === true) {
                // 匿名可访问模式下,给个空数组,控制器里 isset 判断即可
                $request->jwtData = [];
                return $next($request);
            }

            return $this->unauthorized('缺少token', Jwt::TOKEN_EMPTY);
        }

        // 4. 校验 token(签名、时间、黑名单都会查)
        $result = $jwt->Check($token);

        if (empty($result['code'])) {
            if ($this->isOptional($optional) === true) {
                // 匿名模式下 token 无效也放行,但标记为未登录
                $request->jwtData = [];
                return $next($request);
            }

            return $this->unauthorized(
                (string) ($result['msg'] ?? 'token无效'),
                (int) ($result['errno'] ?? Jwt::INVALID_TOKEN)
            );
        }

        // 5. 校验通过,把业务数据挂到请求对象上,控制器用 $request->jwtData 取
        $request->jwtData = $result['data'];

        return $next($request);
    }

    /**
     * 判断当前请求路径是否在放行白名单里
     *
     * 白名单位于 config/jwt.php 的 except,支持 * 通配,例如:
     *   'except' => ['api/login', 'api/register', 'api/captcha/*'],
     *
     * @param Request $request 当前请求对象
     * @return bool 命中白名单返回 true
     */
    protected function inExcept(Request $request): bool
    {
        $path = trim($request->pathinfo(), '/');
        $patterns = (array) config('jwt.except', []);

        foreach ($patterns as $pattern) {
            $pattern = trim((string) $pattern, '/');
            if ($pattern === '') {
                continue;
            }

            // 同时兼容带前导斜杠与不带斜杠两种写法
            if (fnmatch($pattern, $path) === true) {
                return true;
            }

            if (fnmatch('/' . $pattern, '/' . $path) === true) {
                return true;
            }
        }

        return false;
    }

    /**
     * 解析“是否允许匿名访问”
     *
     * 路由上传的参数是字符串(如 'true'、'1'),这里统一转成布尔值;
     * 参数没传时读取 config('jwt.optional')。
     *
     * @param mixed $optional 路由参数或默认值
     * @return bool
     */
    protected function isOptional($optional): bool
    {
        if ($optional === false || $optional === null) {
            // 路由没给参数,走配置默认值
            return filter_var(config('jwt.optional', false), FILTER_VALIDATE_BOOLEAN);
        }

        return filter_var($optional, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * 组装未通过认证时的统一返回
     *
     * 返回 401,响应体结构与 Jwt::Check() 保持一致,
     * errno 用来区分“缺 token / 已过期 / 已注销 / 非法”等情况,前端据此决定是否跳刷新。
     *
     * @param string $msg 错误提示
     * @param int $errno 业务错误码
     * @return Response
     */
    protected function unauthorized(string $msg, int $errno): Response
    {
        return json([
            'code' => 0,
            'msg' => $msg,
            'data' => '',
            'errno' => $errno,
        ], 401);
    }
}
