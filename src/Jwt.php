<?php

declare(strict_types=1);

namespace think;

use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;
use Firebase\JWT\Key;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

/**
 * ThinkPHP 8.0+ Jwt 验证
 *
 * 基于 firebase/php-jwt ^7.2，提供 token 的签发、校验、刷新、注销，
 * 以及黑名单（基于 cache）与请求头 token 提取能力。
 *
 * 两个时间参数的含义务必分清：
 * - exp     ：签发后多久“要求刷新”，到点后 Check() 返回失败，前端应调 Refresh() 换新 token
 * - refresh ：token 的实际有效期，也就是 payload 里 exp 的值
 *
 * @package think\Jwt
 */
class Jwt
{
    /** @var array 配置项，来自 config('jwt') */
    protected $cfg = [];

    /** @var string 加密秘钥 */
    protected $secret = '';

    /** @var int 签发后多久要求刷新（秒），默认 10 小时，可用参数名 exp 配置 */
    protected $exp = 36000;

    /** @var int token 实际有效期（秒），默认 7 天，对应 payload 的 exp */
    protected $refresh = 604800;

    public const ENCRYPT_EORROR = 50001; //jwt加密算法运算时异常
    public const JWT_SECRET_MISS = 50002; //jwt加密秘钥值未设置
    public const INVALID_TOKEN = 40001; //token格式不正确不合法,异常的token
    public const TOKEN_EMPTY = 40002; //请求没有携带token
    public const TOKEN_EXPIRE = 20001; //token签发超过exp,需要刷新
    public const TOKEN_EXPIRE_LONG = 20002; //token过期,过期时间超过上限
    public const TOKEN_LOGOUT = 20003; //token已经被注销
    public const TOKEN_DOMAIN = 20004; //token签名算法或密钥不匹配

    /**
     * 根据配置文件设置相关参数
     *
     * @throws \Exception 秘钥未设置时抛出
     */
    public function __construct()
    {
        // config('jwt') 在配置未发布时返回 null，这里统一转成数组处理
        $this->cfg = (array) config('jwt');

        $this->secret = !empty($this->cfg['secret']) ? (string) $this->cfg['secret'] : '';
        if ($this->secret === '') {
            throw new \Exception('未设置jwt秘钥', self::JWT_SECRET_MISS);
        }

        // firebase/php-jwt 7.x 会校验 HMAC 密钥长度:HS256 要求至少 32 字节,
        // 否则底层直接抛 "Provided key is too short"。
        // 配置里的 secret 通常是一段普通字符串,这里无论长短统一过一遍 deriveKey() 转成 32 字节密钥
        if ($this->secret !== '') {
            $this->secret = $this->deriveKey($this->secret);
        }

        // exp：签发后多久要求刷新(不是token失效时间),默认 10 小时
        $this->exp = !empty($this->cfg['exp']) ? (int) $this->cfg['exp'] : ((60 * 60) * 10);

        // refresh：token 的实际有效期,默认 7 天
        $this->refresh = !empty($this->cfg['refresh']) ? (int) $this->cfg['refresh'] : (((60 * 60) * 24) * 7);
    }

    /**
     * 把配置里的秘钥字符串转换成 HS256 能用的密钥
     *
     * firebase/php-jwt 7.x 对 HMAC 密钥有长度校验:HS256 要求至少 32 字节(256 位),
     * 配置里写一段普通短字符串(例如 15 个字符)会因为太短直接抛 "Provided key is too short",
     * 所以这里统一做一次 SHA-256 派生,产出固定的 32 字节二进制密钥,配置里就不用写超长串了。
     *
     * 三点说明:
     * - 派生结果是确定的,同一个 secret 每次都得到同一个密钥,签发与校验能正常互通
     * - 不论配置里给的是长串还是短串,都统一派生一次,行为固定,不会因为换了密钥长度而变化
     * - 派生只补足长度,不增加真实强度,生产环境仍建议直接配置 32 字节以上的随机串
     *
     * @param string $secret 配置里的原始秘钥字符串
     * @return string 实际参与签名的密钥
     */
    protected function deriveKey(string $secret): string
    {
        // 第三个参数为 true 时返回 32 字节二进制串,正好满足 HS256 的 256 位要求
        return hash('sha256', $secret, true);
    }

    /**
     * 获取token
     * 该方法用于生成包含特定数据的JWT(JSON Web Token)
     *
     * @param array $data 数据负载,即将被编码进JWT的数据部分
     * @return string 生成的JWT字符串
     * @throws \Exception 生成失败时抛出,错误码 ENCRYPT_EORROR
     */
    public function getToken($data = [])
    {
        // 获取当前时间,用于设置JWT的生效时间和过期时间
        $now = time();

        // token 的实际失效时间 = 当前时间 + refresh
        $expire_time = $now + $this->refresh;

        // 生成一个随机标识,用于 JWT 的唯一 id 与黑名单
        $keyId = $this->Random();

        // 定义JWT的载荷,包含签发时间、生效时间、过期时间、JWT标识和数据
        $payload = [
            'iat' => $now, // 签发时间,标准字段
            'nbf' => $now, // 生效时间
            'exp' => $expire_time, // 失效时间
            'jwt_ide' => $keyId, // 为JWT分配一个唯一的标识,注销时写黑名单用
            'data' => $data, // 包含需要传递的数据
        ];

        try {
            // 使用JWT库的encode方法生成令牌,同时指定载荷、秘钥、算法和密钥标识
            return \Firebase\JWT\JWT::encode($payload, $this->secret, 'HS256', $keyId);
        } catch (\Throwable $e) {
            // 生成过程出错统一转成自定义错误码,方便调用方识别
            throw new \Exception('生成令牌失败:' . $e->getMessage(), self::ENCRYPT_EORROR);
        }
    }

    /**
     * 验证令牌(Token)的有效性
     *
     * 先解析令牌(会做签名、生效时间、失效时间、黑名单校验),
     * 再判断签发时间是否已经超过 exp,超过则提示“需要刷新”。
     *
     * 返回结构固定为 code / msg / data / errno 四个键:
     * - code  1 表示通过,0 表示失败
     * - msg   失败原因
     * - data  通过时是业务数据,失败时是空字符串
     * - errno 失败时的业务错误码(对应类里的常量),通过时为 0
     *
     * @param string $token 待验证的令牌字符串
     * @return array 校验结果
     */
    public function Check($token = '')
    {
        $json = [];
        $json['code'] = 0;
        $json['msg'] = '';
        $json['data'] = '';
        $json['errno'] = 0;

        // 没传 token 时直接返回,避免拿空串去解码
        if ($token === '' || $token === null) {
            $json['msg'] = '缺少token';
            $json['errno'] = self::TOKEN_EMPTY;
            return $json;
        }

        try {
            // 解析传入的令牌,获取令牌中的数据和标识
            $arr = $this->Parse($token, 1);

            // 签发时间优先取标准字段 iat,老 token 没有 iat 时退回 nbf
            $issuedAt = (int) ($arr['iat'] ?? $arr['nbf'] ?? 0);

            // 判断是否已经超过刷新窗口:是“当前时间 - 签发时间”,不是“签发时间 - 当前时间”
            if ($issuedAt > 0 && (time() - $issuedAt) >= $this->exp) {
                throw new \Exception('token过期需要刷新', self::TOKEN_EXPIRE);
            }

            $json['code'] = 1;
            $json['data'] = $arr['data'] ?? [];
        } catch (\Exception $e) {
            $json['msg'] = $e->getMessage();
            $json['errno'] = (int) $e->getCode();
        }

        return $json;
    }

    /**
     * 刷新令牌
     * 本函数用于刷新已经过期或即将过期的令牌
     * 它首先解析传入的令牌,将旧令牌加入黑名单,然后基于解析出的数据生成一个新的令牌
     *
     * @param string $token 待刷新的令牌
     * @return array 刷新结果,code=1 时 data 是新 token
     */
    public function Refresh($token = '')
    {
        $json = [];
        $json['code'] = 0;
        $json['msg'] = '';
        $json['data'] = '';
        $json['errno'] = 0;

        try {
            // 解析传入的令牌,获取令牌中的数据和标识
            $arr = $this->Parse($token, 1);

            // 没有唯一标识就无法写黑名单,这种 token 不允许刷新
            if (empty($arr['jwt_ide'])) {
                throw new \Exception('token缺少唯一标识', self::INVALID_TOKEN);
            }

            // 将旧令牌标识加入黑名单,防止同一个旧 token 被重复使用
            $this->AddBlacklist((string) $arr['jwt_ide']);

            // 基于令牌里的业务数据生成并返回新令牌
            $data = $this->getToken($arr['data'] ?? []);
            $json['code'] = 1;
            $json['msg'] = '刷新令牌成功';
            $json['data'] = $data;
        } catch (\Exception $e) {
            $json['msg'] = $e->getMessage();
            $json['errno'] = (int) $e->getCode();
        }

        return $json;
    }

    /**
     * 注销令牌
     * 通过解析令牌,然后把该令牌的唯一标识写入黑名单,阻止它之后继续使用
     *
     * @param string $token 待注销的令牌字符串
     * @return array 注销结果,code=1 表示成功
     */
    public function Logout($token = '')
    {
        $json = [];
        $json['code'] = 0;
        $json['msg'] = '';
        $json['data'] = '';
        $json['errno'] = 0;

        try {
            // 解析传入的令牌,获取令牌中的数据
            $arr = $this->Parse($token, 1);

            if (empty($arr['jwt_ide'])) {
                throw new \Exception('token缺少唯一标识', self::INVALID_TOKEN);
            }

            // 将令牌标识加入黑名单,有效期与 token 本身一致
            $this->AddBlacklist((string) $arr['jwt_ide']);
            $json['code'] = 1;
            $json['msg'] = '注销令牌成功';
        } catch (\Exception $e) {
            $json['msg'] = $e->getMessage();
            $json['errno'] = (int) $e->getCode();
        }

        return $json;
    }

    /**
     * 解析并验证JWT令牌
     *
     * 依次做签名校验、生效时间校验、失效时间校验,再查黑名单。
     * 注意异常捕获顺序:firebase 的 ExpiredException、BeforeValidException、
     * SignatureInvalidException 都继承自 UnexpectedValueException,
     * 所以子类必须写在父类前面,否则会被父类一口吞掉,永远命中不到。
     *
     * @param string $token 待解析的JWT令牌
     * @param int $type 返回类型,0为用户业务数据,1为完整载荷,默认为0
     * @return array 解码后的数据
     * @throws \Exception 秘钥未设置、格式异常、签名无效、尚未生效、已过期或已注销时抛出
     */
    public function Parse($token = '', $type = 0)
    {
        // 空 token 直接拒绝,避免底层库抛出难以理解的异常
        if ($token === '' || $token === null) {
            throw new \Exception('缺少token', self::TOKEN_EMPTY);
        }

        try {
            // 使用JWT库解码令牌,同时校验签名
            $token_obj = \Firebase\JWT\JWT::decode($token, new Key($this->secret, 'HS256'));
        } catch (ExpiredException $e) {
            // 令牌已过期,超出 refresh 的有效期上限
            throw new \Exception('令牌已过期:' . $e->getMessage(), self::TOKEN_EXPIRE_LONG);
        } catch (BeforeValidException $e) {
            // 令牌尚未生效(nbf 还在未来)
            throw new \Exception('令牌尚未生效:' . $e->getMessage(), self::INVALID_TOKEN);
        } catch (SignatureInvalidException $e) {
            // 签名校验失败,可能被篡改
            throw new \Exception('签名无效:' . $e->getMessage(), self::INVALID_TOKEN);
        } catch (UnexpectedValueException $e) {
            // 结构或字段异常,例如缺少必要字段、算法不支持
            throw new \Exception('令牌格式异常:' . $e->getMessage(), self::INVALID_TOKEN);
        } catch (InvalidArgumentException $e) {
            // 秘钥或参数不合法
            throw new \Exception('未设置jwt秘钥', self::JWT_SECRET_MISS);
        } catch (DomainException $e) {
            // 算法或密钥类型不匹配
            throw new \Exception('签名算法或密钥不匹配:' . $e->getMessage(), self::TOKEN_DOMAIN);
        }

        // 检查解码后的令牌是否在黑名单中(已注销的 token 不允许再用)
        $jwtIde = (string) ($token_obj->jwt_ide ?? '');
        if ($jwtIde !== '' && $this->InBlacklist($jwtIde) === true) {
            throw new \Exception('token已被注销', self::TOKEN_LOGOUT);
        }

        $result = $this->objectToArray($token_obj);

        // type=0 时只返回业务数据,type=1 时返回完整载荷
        if ($type == 0) {
            return $result['data'] ?? [];
        }

        return $result;
    }

    /**
     * 获取请求头中的Authorization字段,用于提取token
     *
     * 从 $_SERVER 里取,适合没有 Request 对象的场景;
     * 有 Request 对象时请优先用 getRequestToken($request)。
     *
     * @return string 提取到的token,不存在时返回空字符串
     */
    public function getRequestHeaders()
    {
        // 检查HTTP_AUTHORIZATION环境变量是否存在
        if (empty($_SERVER['HTTP_AUTHORIZATION'])) {
            return '';
        }

        return $this->parseTokenFromHeader((string) $_SERVER['HTTP_AUTHORIZATION']);
    }

    /**
     * 从请求中获取授权令牌
     *
     * 优先读 Authorization 头,取不到时再读服务器重写后留下的备用头。
     *
     * @param Request $request 请求对象
     * @return string 提取到的token,不存在时返回空字符串
     */
    public function getRequestToken($request)
    {
        // 先读标准的 Authorization 头
        $authorization = '';
        if (is_object($request) && method_exists($request, 'header')) {
            $value = $request->header('authorization');
            $authorization = is_string($value) ? $value : '';
        }

        // 标准头为空时,尝试备用头
        if ($authorization === '' && is_object($request) && method_exists($request, 'header')) {
            $authorization = $this->getFromAltHeaders($request);
        }

        return $this->parseTokenFromHeader($authorization);
    }

    /**
     * 从请求的备用头部中获取认证信息
     *
     * 部分服务器(Apache CGI、重写规则)会把 Authorization 挪到
     * REDIRECT_HTTP_AUTHORIZATION,这里按这个顺序兜底。
     *
     * @param Request $request 请求对象
     * @return string 认证头部原文
     */
    protected function getFromAltHeaders(Request $request)
    {
        $redirect = (string) $request->server('REDIRECT_HTTP_AUTHORIZATION', '');
        if ($redirect !== '') {
            return $redirect;
        }

        return (string) $request->server('HTTP_AUTHORIZATION', '');
    }

    /**
     * 从 Authorization 头部值里取出 token 本身
     *
     * 只去掉开头的 “Bearer ” 前缀,不用 str_ireplace 全串替换,
     * 避免 token 内部恰好含有 bearer 字样时被误伤。
     *
     * @param string $header 头部原文,例如 “Bearer abc.def.ghi”
     * @return string token 本身,取不到时返回空字符串
     */
    protected function parseTokenFromHeader($header)
    {
        $header = trim((string) $header);
        if ($header === '') {
            return '';
        }

        // 前缀不区分大小写,但必须出现在开头且带空白
        if (stripos($header, 'bearer ') === 0) {
            return trim(substr($header, 7));
        }

        return $header;
    }

    /**
     * 检查JWT标识是否在黑名单中
     *
     * @param string $jwt_ide JWT标识符
     * @return bool 在黑名单中返回 true
     * @throws \Exception 缓存不可用时抛出,这里选择“失败即拒绝”而不是放行
     */
    protected function InBlacklist($jwt_ide = '')
    {
        $key = 'jwt_ide_' . $jwt_ide;

        try {
            // 缓存里没有值就视为没有注销
            if (!cache($key)) {
                return false;
            }
        } catch (\Throwable $e) {
            // 缓存不可用时不能静默放行,否则黑名单形同虚设
            throw new \Exception('缓存不可用,无法校验token状态:' . $e->getMessage(), self::ENCRYPT_EORROR);
        }

        return true;
    }

    /**
     * 将JWT标识添加到黑名单
     *
     * @param string $jwt_ide JWT标识符
     * @return bool 写入成功返回 true
     */
    protected function AddBlacklist($jwt_ide = '')
    {
        $key = 'jwt_ide_' . $jwt_ide;

        // 缓存时长与 token 有效期一致,过期后黑名单自动释放
        cache($key, 1, $this->refresh);

        return true;
    }

    /**
     * 生成指定长度的随机字符串
     *
     * 用作 JWT 唯一标识,必须不可预测,所以用 random_int(CSPRNG)
     * 而不是 mt_rand(可预测的伪随机)。
     *
     * @param int $length 随机字符串长度,默认16
     * @return string 生成的随机字符串
     */
    public function Random($length = 16)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $max = strlen($chars) - 1;
        $str = '';

        for ($i = 0; $i < (int) $length; $i++) {
            $str .= $chars[random_int(0, $max)];
        }

        return $str;
    }

    /**
     * 将对象转换为数组
     * 递归处理对象中的所有属性,直到所有元素都是基本类型
     *
     * @param mixed $obj 要转换的对象或数组
     * @return array 转换后的数组
     */
    public function objectToArray($obj)
    {
        $_arr = is_object($obj) ? get_object_vars($obj) : $obj;

        // 入参为空数组时下面的循环不会执行,先初始化,避免返回未定义变量
        $result = [];
        if (!is_array($_arr)) {
            return $result;
        }

        foreach ($_arr as $key => $val) {
            // 数组或对象继续递归,其余原样保留
            $result[$key] = (is_array($val) || is_object($val)) ? $this->objectToArray($val) : $val;
        }

        return $result;
    }
}
