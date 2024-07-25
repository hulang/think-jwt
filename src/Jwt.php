<?php

declare(strict_types=1);

namespace think;

use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;

class Jwt
{
    protected $secret = '';
    protected $exp = 3600; //一小时
    protected $refresh = 604800; //七天
    const ENCRYPT_EORROR = 50001; //jwt加密算法运算时异常
    const JWT_SECRET_MISS = 50002; //jwt加密秘钥值未设置
    const INVALID_TOKEN = 40001; //token格式不正确不合法,异常的token
    const TOKEN_EXPIRE = 20001; //token过期,需要刷新
    const TOKEN_EXPIRE_LONG = 20002; //token过期,过期时间超过上限
    const TOKEN_LOGOUT = 20003; //token已经被注销
    const TOKEN_DOMAIN = 20004; //token已经被注销

    /**
     * 根据配置文件设置相关参数
     * @return $this
     */
    public function __construct()
    {
        $this->secret = config('jwt.secret') ? config('jwt.secret') : '';
        if ($this->secret == '') {
            throw new \Exception('未设置jwt秘钥', self::JWT_SECRET_MISS);
        }
        $this->exp = config('jwt.exp') ? config('jwt.exp') : 3600;
        $this->refresh = config('jwt.refresh') ? config('jwt.refresh') : 604800;
    }

    /**
     * 获取token
     * 该方法用于生成包含特定数据的JWT(JSON Web Token)
     * @param $data 数据负载,即将被编码进JWT的数据部分
     * @return mixed|string 生成的JWT字符串,如果发生错误则抛出异常
     */
    public function getToken($data)
    {
        // 获取当前时间,用于设置JWT的生效时间和过期时间
        $invali_time = time();
        $expire_time = time() + $this->refresh;
        // 生成一个随机的keyId,用于JWT的标识
        $keyId = $this->Random();
        // 定义JWT的载荷,包含生效时间、过期时间、JWT标识和数据
        $payload = [
            'nbf' => $invali_time, // Not Before,指定JWT在什么时间之后才有效
            'exp' => $expire_time, //Expiration Time,指定JWT在什么时间之后失效
            'jwt_ide' => $keyId, // 为JWT分配一个唯一的标识
            'data' => $data, // 包含需要传递的数据
        ];
        try {
            // 使用JWT库的encode方法生成令牌,同时指定载荷、秘钥和算法
            // 还包括了JWT的keyId,用于标识这个JWT
            return \Firebase\JWT\JWT::encode($payload, $this->secret, 'HS256', $keyId);
        } catch (\Exception $e) {
            // 如果在生成JWT的过程中发生错误,抛出一个自定义的异常
            throw new \Exception('数据加密出错', self::ENCRYPT_EORROR);
        }
    }

    /**
     * 验证令牌(Token)的有效性
     * 
     * 本函数主要用于通过令牌验证用户身份或访问权限
     * 它首先会对传入的令牌进行解析,然后检查令牌的生效时间是否在当前时间之前
     * 如果令牌尚未生效或已经过期,将会抛出异常
     * 如果令牌有效,則会将其转换为数组形式并返回
     * 
     * @param string $token 待验证的令牌字符串.默认为空,表示使用默认的令牌
     * @return mixed|array 如果令牌有效,返回解析后的令牌数据(转换为数组形式);否则,抛出异常
     * @throws \Exception 如果令牌过期,则抛出异常,异常信息包括“token过期需要刷新”,并附带特定错误码
     */
    public function Check($token = '')
    {
        // 解析令牌,获取令牌中的信息对象
        $token_obj = $this->Parse($token);
        // 检查令牌的生效时间是否在当前时间之前,如果令牌尚未生效或已经过期,则抛出异常
        if ($token_obj->nbf - time() >= $this->exp) {
            throw new \Exception('token过期需要刷新', self::TOKEN_EXPIRE);
        }
        // 令牌有效,将令牌信息对象转换为数组形式并返回
        return $this->objectToArray($token_obj);
    }

    /**
     * 刷新令牌
     * 本函数用于刷新已经过期或即将过期的令牌
     * 它首先解析传入的令牌,将旧令牌加入黑名单,然后基于解析出的数据生成一个新的令牌
     * 
     * @param string $token 待刷新的令牌,默认为空.如果为空,函数可能需要从其他来源获取令牌
     * @return mixed|string 返回新的令牌字符串.如果操作失败,可能返回其他类型的数据,具体取决于实现
     */
    public function Refresh($token = '')
    {
        // 解析传入的令牌,获取令牌中的数据和标识
        $token_obj = $this->Parse($token);
        // 将旧令牌标识加入黑名单,防止重复使用
        $this->AddBlacklist($token_obj->jwt_ide);
        // 基于令牌数据生成并返回新令牌
        return $this->getToken($token_obj->data);
    }

    /**
     * 注销令牌
     * 
     * 本函数用于标记一个令牌为无效,实现令牌的注销功能
     * 它通过解析令牌,然后将该令牌添加到黑名单中,以阻止该令牌未来的使用
     * 
     * @param string $token 待注销的令牌字符串
     * @return mixed|bool 成功注销返回true,过程中发生错误则返回错误信息
     */
    public function Logout($token)
    {
        // 解析令牌,获取令牌中的标识信息
        $token_obj = $this->Parse($token);
        // 将解析出的令牌标识添加到黑名单中
        $this->AddBlacklist($token_obj->jwt_ide);
        // 注销成功,返回true
        return true;
    }

    /**
     * 解析并验证JWT令牌
     * 
     * 该方法尝试解码给定的JWT令牌,并进行一系列验证
     * 如果令牌解码或验证失败,将抛出相应的异常
     * 
     * @param string $token 待解析的JWT令牌
     * @return mixed|array|Exception 解码后的JWT对象,如果失败则抛出异常
     * 
     * @throws Exception 如果JWT秘钥未设置、令牌格式异常、签名无效、令牌过期或令牌在黑名单中,则抛出相应的异常
     */
    public function Parse($token)
    {
        try {
            // 使用JWT库解码令牌,检查是否设置了秘钥
            $token_obj = \Firebase\JWT\JWT::decode($token, new Key($this->secret, 'HS256'));
        } catch (InvalidArgumentException $e) {
            // 抛出异常：秘钥未设置
            throw new \Exception('未设置jwt秘钥', self::JWT_SECRET_MISS);
        } catch (UnexpectedValueException $e) {
            // 抛出异常：令牌格式异常
            throw new \Exception('token格式异常:' . $e->getMessage(), self::INVALID_TOKEN);
        } catch (SignatureInvalidException $e) {
            // 抛出异常：签名无效
            throw new \Exception('token格式异常:' . $e->getMessage(), self::INVALID_TOKEN);
        } catch (BeforeValidException $e) {
            // 抛出异常：令牌尚未生效
            throw new \Exception('token失效:' . $e->getMessage(), self::INVALID_TOKEN);
        } catch (ExpiredException $e) {
            // 抛出异常：令牌已过期
            throw new \Exception('token完全失效:' . $e->getMessage(), self::TOKEN_EXPIRE_LONG);
        } catch (DomainException $e) {
            // 抛出异常：令牌已过期
            throw new \Exception('token域名失效:' . $e->getMessage(), self::TOKEN_DOMAIN);
        }
        // 检查解码后的令牌是否在黑名单中
        if ($this->InBlacklist($token_obj->jwt_ide) === true) {
            // 抛出异常：令牌已被注销
            throw new \Exception('token已被注销', self::TOKEN_LOGOUT);
        }
        // 返回解码并验证通过的令牌对象
        return $token_obj;
    }

    /**
     * 检查JWT标识是否在黑名单中
     * 
     * 本函数用于验证给定的JWT标识是否已被标记为无效,即是否存在于黑名单中
     * 如果JWT标识存在于黑名单中,表示该令牌已被注销,不能再用于授权访问
     * 
     * @param string $jwt_ide JWT标识符,用于在黑名单中进行查找
     * @return mixed|bool 如果JWT标识存在于黑名单中,则返回true;否则返回false
     */
    protected function InBlacklist($jwt_ide)
    {
        // 构建缓存键名,前缀为'jwt_ide_',后缀为JWT标识符
        $key = 'jwt_ide_' . $jwt_ide;
        // 尝试从缓存中获取指定键名的值,如果不存在则返回false
        if (!cache($key)) {
            return false;
        }
        // 如果缓存中存在指定键名的值,表示JWT标识存在于黑名单中,返回true
        return true;
    }

    /**
     * 将JWT标识添加到黑名单
     * 该方法用于将给定的JWT标识添加到系统的黑名单中,以禁止该令牌未来的使用
     * 主要用于令牌过期或需要提前吊销的情况
     *
     * @param string $jwt_ide JWT标识符,用于唯一标识一个令牌
     * @return mixed|bool 如果添加成功,返回true;否则返回错误信息
     */
    protected function AddBlacklist($jwt_ide)
    {
        // 构建缓存键名,以JWT标识为键,添加到黑名单缓存中
        $key = 'jwt_ide_' . $jwt_ide;
        // 将JWT标识符及其对应的值(这里使用1作为占位符)缓存起来,缓存有效期为$refresh时间
        // 这里的缓存机制用于标记该JWT标识为无效,实际应用中可以根据需求调整缓存策略
        cache($key, 1, $this->refresh);
        // 添加成功后,返回true
        return true;
    }

    /**
     * 生成指定长度的随机字符串
     * 
     * 本函数用于生成一个包含大小写字母和数字的随机字符串
     * 此功能可以用于生成密码、验证码、或其他需要随机字符串的场景
     * 
     * @param int $length 指定生成的随机字符串的长度.默认为16
     * @return mixed|string 返回生成的随机字符串.如果发生错误,可能返回NULL
     */
    public function Random($length = 16)
    {
        // 定义包含所有可能字符的字符串,包括大小写字母和数字
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        // 初始化随机字符串
        $str = '';
        // 循环生成随机字符串
        for ($i = 0; $i < $length; $i++) {
            // 从所有可能字符中随机选择一个字符,并将其添加到随机字符串中
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        // 返回生成的随机字符串
        return $str;
    }

    /**
     * 将对象转换为数组
     * 这个函数递归处理对象中的所有属性,确保所有属性都被转换为数组形式
     * 如果属性是对象或数组,则递归调用自身进行转换,直到所有元素都是基本类型
     * 
     * @param mixed $obj 要转换的对象或数组
     * @return mixed|array 转换后的数组
     */
    public function objectToArray($obj)
    {
        // 检查参数是否为对象,如果是则获取其属性,如果不是则直接使用
        $_arr = is_object($obj) ? get_object_vars($obj) : $obj;
        // 递归处理每个元素,确保所有元素都被转换为数组
        foreach ($_arr as $key => $val) {
            // 如果当前元素是数组或对象,则递归调用自身进行转换
            $val = (is_array($val) || is_object($val)) ? self::objectToArray($val) : $val;
            // 将转换后的元素添加到结果数组中
            $arr[$key] = $val;
        }
        // 返回转换后的数组
        return $arr;
    }
}