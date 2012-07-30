<?php
/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2004 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the PHP license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_0.txt.                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  Harun Yayli <harunyayli at gmail.com>                       |
  +----------------------------------------------------------------------+
*/

$VERSION='$Id: Redismon.php 310129 2012-05-29 03:04:27Z David $';

define('ADMIN_USERNAME','Redis'); 	// Admin Username
define('ADMIN_PASSWORD','password');  	// Admin Password
define('DATE_FORMAT','Y/m/d H:i:s');
define('GRAPH_SIZE',200);
define('MAX_ITEM_DUMP',50);

$REDIS_SERVERS[] = '192.168.8.203:6370:1024000'; // add more as an array
$REDIS_SERVERS[] = '192.168.8.203:6371:1024000'; // add more as an array


////////// END OF DEFAULT CONFIG AREA /////////////////////////////////////////////////////////////

///////////////// Password protect ////////////////////////////////////////////////////////////////
if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) ||
           $_SERVER['PHP_AUTH_USER'] != ADMIN_USERNAME ||$_SERVER['PHP_AUTH_PW'] != ADMIN_PASSWORD) {
			Header("WWW-Authenticate: Basic realm=\"Redis Login\"");
			Header("HTTP/1.0 401 Unauthorized");

			echo <<<EOB
				<html><body>
				<h1>Rejected!</h1>
				<big>Wrong Username or Password!</big>
				</body></html>
EOB;
			exit;
}

class CRedisException extends Exception {}
/**
 * Redis class
 * 
 * @author David
 * @license GPL
 * @version 2.2.4
 */
class CRedis
{

    /**
    * Static instance of self
    *
    * @var object
    */
    protected static $_instance;
    private $_socket;
    private $_unpacked = true;
    private $_serialize = 'json';
    
    const DEFAULT_HOST     = '127.0.0.1';
    const DEFAULT_PORT     = 6379;
    const DEFAULT_DB       = 0;

    const REPLY_STATUS     = '+';
    const REPLY_ERROR      = '-';
    const REPLY_INTEGER    = ':';
    const REPLY_BULK       = '$';
    const REPLY_MULTY_BULK = '*';
    const EOL              = "\r\n";

    ######################################################################
    #       Object options function
    ######################################################################
    protected $_options = array(
        'host'          => self::DEFAULT_HOST,
        'port'          => self::DEFAULT_PORT,
        'db'            => self::DEFAULT_DB,
        'prefix'        => '',
        'password'      => '',
        'persistent'    => false,
        'timeout'       => 60,
        'readTimeout'   => 10,
        'blockingMode'  => true,
    );

    public function __construct(array $options = array())
    {
        $options = array_merge($this->_options, $options);
        $this->setOptions($options);
    }

    public function __destruct()
    {
    }

    public static function getInstance(array $options = array())
    {
        if ( ! isset(self::$_instance)) {
            self::$_instance = new self($options);
        }
        return self::$_instance;
    }
    
    public static function factory(array $options = array())
    {
        return new self($options);
    }

    public function setOptions(array $options)
    {
        foreach($options as $name => $value) {
            $this->setOption($name, $value);
        }
        return $this;
    }

    public function getOptions()
    {
        return $this->_options;
    }

    public function setOption($name, $value)
    {
        if (method_exists($this, "set$name")) {
            return call_user_func(array($this, "set$name"), $value);
        } else if (array_key_exists($name, $this->_options)) {
            $this->_options[$name] = $value;
            return $this;
        } else {
            return false;
        }
    }

    public function getOption($name)
    {
        if (method_exists($this, "get$name")) {
            return call_user_func(array($this, "get$name"));
        } else if (array_key_exists($name, $this->_options)) {
            return $this->_options[$name];
        } else {
            throw new Exception("Unknown option '$name'");
        }
    }

    ######################################################################
    #       get/set options function
    ######################################################################
    public function getHost()
    {
        return $this->_options['host'];
    }

    public function setHost($value)
    {
        $this->_options['host'] = $value;
    }
    
    public function getPort()
    {
        return $this->_options['port'];
    }

    public function setPort($value)
    {
        $this->_options['port'] = $value;
    }

    public function getPrefix()
    {
        return $this->_options['prefix'];
    }

    public function setPrefix($value)
    {
        $this->_options['prefix'] = $value;
    }

    public function setPassword($value)
    {
        $this->_options['password'] = $value;
    }

    public function getPassword()
    {
        return $this->_options['password'];
    }


    public function getPersistent()
    {
        return $this->_options['persistent'];
    }

    public function setPersistent($value)
    {
        $this->_options['persistent'] = $value;
    }

    public function setTimeout($value)
    {
        $this->_options['timeout'] = $value;
    }

    public function getTimeout()
    {
        if (null !== $this->_options['timeout']) {
            return $this->_options['timeout'];
        } else {
            return ini_get('default_socket_timeout');
        }
    }

    public function setReadTimeout($value)
    {
        $this->_options['readTimeout'] = $value;
    }

    public function getReadTimeout()
    {
        return $this->_options['readTimeout'];
    }

    ######################################################################
    #  base function
    ######################################################################
        
    function connect()
    {
        if (!$this->isConnected()) {
            $socketAddress = 'tcp://' . $this->getHost() . ':' . $this->getPort();

            if ($this->getPersistent()) {
                $flag = STREAM_CLIENT_PERSISTENT | STREAM_CLIENT_CONNECT;
            } else {
                $flag = STREAM_CLIENT_CONNECT;
            }
            $this->_socket = @stream_socket_client($socketAddress, $errno, $errmsg, $this->getTimeout(), $flag);

            // Throw exception if can't connect
            if (!is_resource($this->_socket)) {
                $msg = "Can't connect to Redis server on {$this->getHost()}:{$this->getPort()}";
                if ($errno || $errmsg) {
                    $msg .= "," . ($errno ? " error $errno" : "") . ($errmsg ? " $errmsg" : "");
                }

                $this->_socket = null;

                throw new CRedisException($msg);
            }

            // Set read timeout
            $seconds = floor($this->getReadTimeout());
            $microseconds = ($this->getReadTimeout() - $seconds) * 1000000;

            stream_set_timeout($this->_socket, $seconds, $microseconds);
        }

    }

    public function disconnect()
    {
        if ($this->isConnected()) {
            @fclose($this->_socket);

            return true;
        } else {
            return false;
        }
    }
    
    public function isConnected()
    {
        return is_resource($this->_socket);
    }

    protected function write($buffer)
    {
        if ($buffer !== '') {
            $this->connect();
            $this->command = $buffer;
            $buffer = (string)$buffer . self::EOL;

            while (($length = strlen($buffer)) > 0) {
                $bytes = @fwrite($this->_socket, $buffer);
                if ($bytes === false) {
                    $this->disconnect();
                    throw new RedisException("Can't write to socket.");
                }
    
                if ($bytes == 0) {
                    return true;
                }
                $buffer = substr($buffer, $bytes);
            }
        }
    }

    protected function readLine()
    {
        if (!$this->isConnected()) {
            throw new CRedisException("Can't read without connection to Redis server. Do connect or write first.");
        }

        $reply = @fgets($this->_socket);

        $info = stream_get_meta_data($this->_socket);
        if ($info['timed_out']) {
            throw new CRedisException("Connection read timed out.");
        }

        if ($reply === false) {
            if ($this->_options['blockingMode'] || (!$this->_options['blockingMode'] && $info['eof'])) {
                $this->disconnect();
                throw new CRedisException("Can't read from socket.");
            }

            $reply = null;
        } else {
            $reply = trim($reply);
        }

        return $reply;
    }

    protected function _readAndThrowException($length)
    {

        if (!$this->isConnected()) {
            throw new CRedisException("Can't read without connection to Redis server. Do connect or write first.");
        }
        $data = stream_get_contents($this->_socket,$length);
        $info = stream_get_meta_data($this->_socket);
        if ($info['timed_out']) {
            $this->tmied_out = $this->command;
            throw new CRedisException("Connection read timed out.");
        }

        if ($data === false || $data === '')
        {
            $this->disconnect();
            throw new CRedisException("Can't read from socket.");
        }
        
        return $data;
    }

    protected function read($length)
    {
        if (!$this->isConnected()) {
            throw new CRedisException("Can't read without connection to Redis server. Do connect or write first.");
        }

        if ($length > 0) {
            $data = $this->_readAndThrowException($length);
        } else {
            $data = null;
        }

        if ($length !== -1) {
            $this->_readAndThrowException(2);
        }

        return $data;
    }

    protected function getResponse()
    {
    
        $reply = $this->readLine();
        if ($reply === null) {
            return $reply;
        }

        $type = substr($reply, 0, 1);
        $data = substr($reply, 1);

        switch ($type) {
            case self::REPLY_STATUS: // inline
                if ($data == 'OK') {
                    return true;
                } else {
                    return $data;
                }

            case self::REPLY_BULK:
                if ($data == '-1') {
                    return null;
                } else {
                    $length = (integer)$data;
                    return $this->read($length);
                }

            case self::REPLY_MULTY_BULK:
                $count = (integer)$data;
                
                $replies = array();
                for ($i = 0; $i < $count; $i++) {
                    $replies[] = $this->getResponse();
                }
                
                return $replies;

            case self::REPLY_INTEGER:
                if (strpos($data, '.') !== false) {
                    $number = (integer)$data;
                } else {
                    $number = (float)$data;
                }
                return $number;
            case self::REPLY_ERROR:
                $message = substr($data, 4);
                throw new CRedisException($message);

            default:
                throw new CRedisException("Invalid reply type: '$type'");
        }
    }
    
    private function executeCommand( $commands )
    {
        if ( is_array($commands) )
        {
            $command = self::REPLY_MULTY_BULK . count($commands) . self::EOL;
            foreach($commands as $argument) {
                $command .= self::REPLY_BULK . strlen($argument) . self::EOL . $argument . self::EOL;
            }
        }
        else $command = $commands;

        try
        {
            $this->write($command);
            $data = $this->getResponse();
            $this->data = $data;
            return $data;
        }
        catch (CRedisException $e)
        {
            throw new CRedisException($e->getMessage());
            try
            {
                $this->write($command);
                $data = $this->getResponse();
                $this->data = $data;
                return $data;
            }
            catch (CRedisException $e)
            {
                throw new CRedisException($e->getMessage());
            }
        }

    }

    private function packValue( $value )
    {
        if (is_numeric($value) || is_string($value)) {
            return (string)$value;
        } else {
	        if($this->_serialize=='json')
	        {
		        $serializedValue = json_encode($value);
		        return $serializedValue;
		    }
	        else
	        { return serialize($value); }
        }
    }

    private function unpackValue( $value )
    {
	    
        if (is_null($value)) {
            return null;
        } else if (is_numeric($value)) {
            if (strpos($value, '.') === false) {
                $unserializedValue = (integer)$value;
            } else {
                $unserializedValue = (float)$value;
            }

            if ((string)$unserializedValue != $value) {
                $unserializedValue = $value;
            }
        } else {
            try {	            
		        if($this->_serialize=='json')
		        {
			        $unserializedValue = json_decode($value, true);
	                if ($unserializedValue === null && $value !== 'null') {
	                    throw new CRedisException("Can't unpack value");
	                }
	                return $unserializedValue;
			    }
		        else
		        {
                    set_error_handler(array($this, 'catchUnpackError'));
                    $unserializedValue = @unserialize($value);
                    restore_error_handler();
                    if (!$this->_unpacked) {
                        $this->_unpacked = true;
                        throw new CRedisException("Can't unpack value");
                    }
                }
            } catch (CRedisException $e) {
                $unserializedValue = $value;
            }
        }
        return $unserializedValue;
    }

    public function catchUnpackError($errno, $errstr, $errfile, $errline, $errcontext)
    {
        $this->_unpacked = false;
        return true;
    }
    ######################################################################
    #  redis string command
    ######################################################################
    
    function auth($password) {
        $cmd = array('AUTH',$password);
        return $this->executeCommand( $cmd );
    }

    function info() {
        $cmd = array('INFO');
        $result = $this->executeCommand( $cmd );
        $info = array();
        foreach(explode("\n",$result) as $k=>$v)
        {
            if(empty($v))
            {
                continue;
            }
            list($name,$value) = explode(":",$v);
            $info[$name] = $value;
        }
        return $info;
    }
    
    public function select($index)
    {
        $cmd = array("SELECT", $index);
        return $this->executeCommand( $cmd );
    }

    ######################################################################
    #  redis keys command
    ######################################################################
    public function del($key=null)
    {
        if($key===null) throw new CRedisException("redis del key empty.");
        $key = $this->getPrefix().$key;
        $cmd = array("DEL", $key);
        return $this->executeCommand( $cmd );
    }
    
    public function exists($key=null)
    {
        if($key===null) throw new CRedisException("redis exists key empty.");
        $key = $this->getPrefix().$key;
        $cmd = array("EXISTS", $key);
        return $this->executeCommand( $cmd );
    }
    
    public function delete($key)
    {
        return $this->del($key);
    }
    
    ######################################################################
    #  Commands operating on strings
    ######################################################################
    public function get($key=null)
    {
        if($key===null) throw new CRedisException("redis get key empty.");
        if(is_array($key)) return $this->mget();
        
        $key = $this->getPrefix().$key;
        $cmd = "GET {$key}";
        $response = $this->executeCommand( $cmd );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }

    public function mget(array $keys=array())
    {
        if(empty($keys)) throw new CRedisException("redis mget keys empty.");
        $cmd= array('MGET');
        foreach($keys as $key) {
            $cmd[] = $this->getPrefix().$key;
        }
        $response = $this->executeCommand( $cmd );
        $result = array();
        if(is_array($response))
        {
            foreach($response as $key=>$value)
            {
                $result[$keys[$key]] = ($value);
            }
        }
        return $result;
    }
    
    public function set($key=null, $value, $expire=0)
    {
        if($key===null) throw new CRedisException("redis set key empty.");
        $value = $this->packValue($value);

        $key = $this->getPrefix().$key;
        if($expire>0)
        {
            $cmd = array("SETEX", $key, $expire, $value);
        }
        else
        {
            $cmd = array("SET", $key, $value);
        }
        return $this->executeCommand( $cmd );
    }
    
    public function mset($keys=array(), $value=array(), $expire=0){
         if(empty($keys)){
              throw new CRedisException("redis set keys empty.");
         }
         $result=array();
         $cmd=array('MSET');
         foreach ($keys  as $k=>$v){
              $cmd[]=$this->getPrefix().$v;
              $arr=$value[$k];
              $val=implode(',',$arr);
              $cmd[]=$val;
         }
         return $this->executeCommand($cmd);
    }
    
    public function incr($key=null)
    {
        if($key===null) throw new CRedisException("redis incr key empty.");

        $key = $this->getPrefix().$key;
        $cmd = array("INCR", $key);

        return $this->executeCommand( $cmd );
    }
    
    public function incrby($key=null, $num)
    {
        if($key===null) throw new CRedisException("redis incrby key empty.");

        $key = $this->getPrefix().$key;
        $cmd = array("INCRBY", $key, $num);

        return $this->executeCommand( $cmd );
    }
    
    public function decr($key=null)
    {
        if($key===null) throw new CRedisException("redis decr key empty.");

        $key = $this->getPrefix().$key;
        $cmd = array("DECR", $key);

        return $this->executeCommand( $cmd );
    }
    
    ######################################################################
    #  Commands operating on lists
    ######################################################################

    function lpush($key, $value)
    {
        $value = $this->packValue($value);
        $key = $this->getPrefix().$key;
        return $this->executeCommand( array('LPUSH', $key, $value) );
    }

    function rpush($key, $value)
    {
        $value = $this->packValue($value);
        $key = $this->getPrefix().$key;
        return $this->executeCommand( array('RPUSH', $key, $value) );
    }

    function lpop($key) {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array('LPOP', $key) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }
    
    function rpop($key)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array('RPOP', $key) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }
    
    function llen($key)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array('LLEN', $key) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }

    function lrange($key, $start, $end)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array("LRANGE", $key, $start, $end) );
        $result = array();
        if(is_array($response))
        {
            foreach($response as $key=>$value)
            {
                $result[$key] = $this->unpackValue($value);
            }
        }
        return $result;
    }
    
    function ltrim($key, $start, $end)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array("LTRIM", $key, $start, $end) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }

    function lindex($key, $index)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array("LINDEX", $key, $start, $end) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }
    
    function lset($key, $value, $index)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array("LSET", $key, $index, $value) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }

    function lrem($key, $value, $count=1)
    {
        $key = $this->getPrefix().$key;
        $response = $this->executeCommand( array("LREM", $key, $index, $value) );
        if(!empty($response)) return $this->unpackValue($response);
        return $response;
    }

    ######################################################################
    #  Commands operating on hashes
    ######################################################################

    function hdel($key, $field)
    {
        $key = $this->getPrefix().$key;
        return $this->executeCommand(array('HDEL',$key,$field));
    }
    
    function hexists($key, $field)
    {   
        $key = $this->getPrefix().$key;
        return $this->executeCommand(array('HEXISTS',$key,$field));
    }

    function hget($key, $field)
    {
        $key = $this->getPrefix().$key;
        $response=$this->executeCommand(array('HGET',$key,$field));
        if(!empty($response)) return $this->unpackValue($response);
        return $response; 
    }

    function hmget($key, $fields=array())
    {   
        $key = $this->getPrefix().$key;
        if(empty($fields)) return false;
        $cmd=array('HMGET');
        $cmd[]=$key;
        foreach($fields as $k=>$value)
        {
	        if(!empty($value))
	        {
                $cmd[]=$value;
            }
        }
        $response=$this->executeCommand($cmd);

        $result = array();
        if(is_array($response))
        {
            foreach($response as $key=>$value)
            {
                $result[$fields[$key]] = $this->unpackValue($value);
            }
        }
        return $result;
    }
    
    function hgetall($key)
    {
        $key = $this->getPrefix().$key;
        $response=$this->executeCommand(array('HGETALL',$key));
        $result = array();

        if(is_array($response))
        {
            while(count($response)>0)
            {
	            $k = array_shift($response);
	            $v = array_shift($response);
                $result[$k] = $this->unpackValue($v);
            }
        }
        
        return $result;
    }

    function hset($key, $field, $value)
    {
        $key = $this->getPrefix().$key;
        $value = $this->packValue($value);
        return $this->executeCommand(array('HSET',$key,$field,$value));
       
    }

    function hmset($key, $fields=array(), $values=array())
    {
        $key = $this->getPrefix().$key; 
        if(empty($fields)||empty($values)) return false;
        $cmd=array('HMSET');
        $cmd[]=$key;
        foreach ($fields as $k=>$v){
	         
             $cmd[]=$v;
             $cmd[]=$this->packValue($values[$k]);
        }
        return $this->executeCommand($cmd);
    }

    function hlen($key)
    {
        $key = $this->getPrefix().$key;
        return $this->executeCommand(array('HLEN',$key));
    }

    function hsetnx($key,$field,$value)
    {
        $key = $this->getPrefix().$key;
        return $this->executeCommand(array('HSETNX',$key,$field,$value));
    }
    
    function hincrby($key, $field,$increment=1)
    {
        $key = $this->getPrefix().$key;
        return $this->executeCommand(array('HINCRBY',$key,$field,$increment));
    }

    function hkeys($key)
    {
        $key = $this->getPrefix().$key;
        $response=$this->executeCommand(array('HKEYS',$key));
        if(!empty($response)){
            return $this->unpackValue($response);
        }
        return $response; 
    }
    
    function hvals($key)
    {
        $key = $this->getPrefix().$key;
        $response=$this->executeCommand(array('HVALS',$key));
        if(!empty($response)){
            return $this->unpackValue($response);
        }
        return $response; 
    }
    ######################################################################
    #  Commands operating on sorted set
    ######################################################################
    function zadd($key,$score,$member){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZADD',$key,$score,$member));
    }

    function zrem($key,$member){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZREM',$key,$member));
    }

    function zcard($key,$member){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZCARD',$key,$member));
    }
    function zscore($key,$member){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZSCORE',$key,$member));
    }
    function zcount($key,$min,$max){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZCOUNT',$key,$min,$max));
    }

    function zincrby($key,$increment,$member){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZINCRBY',$key,$increment,$member));
    }

    function zrangebyscore($key,$min,$max){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZRANGEBYSCORE',$key,$min,$max));
    }

    function zrevrange($key,$start,$end){
    	$key = $this->getPrefix().$key;
    	return $this->executeCommand(array('ZREVRANGE',$key,$start,$end));
    }
    ######################################################################
    #  Commands Transactions
    ######################################################################
    function multi(){
    	return $this->executeCommand(array('multi'));
    }
    function discard(){
    	return $this->executeCommand(array('DISCARD'));
    }
    function exec(){
    	return $this->executeCommand(array('EXEC'));
    }
}
///////////Redis FUNCTIONS /////////////////////////////////////////////////////////////////////

function get_host_port_from_server($server){
	$values = explode(':', $server);
	if (($values[0] == 'unix') && (!is_numeric( $values[1]))) {
		return array($server, 0);
	}
	else {
		return $values;
	}
}

function getRedisStats($total=true){
    
    global $REDIS_SERVERS;
	$resp = array();
	foreach($REDIS_SERVERS as $server){
		$strs = get_host_port_from_server($server);
		$host = $strs[0];
		$port = $strs[1];
		$cache = new CRedis(array('host'=>$host, 'port'=>$port));
		$resp[$server] = $cache->info();
		$resp[$server]['maxmemory'] = isset($strs[2])?$strs[2]:0;
		
	}
	
	if ($total){
		$res = array();
		foreach($resp as $server=>$r){
			foreach($r as $key=>$row){
				if (!isset($res[$key])){
					$res[$key]=null;
				}
				
				switch ($key){
					case 'uptime_in_seconds':
						$res['uptime_in_seconds'][$server]=$row;
						break;
    				case 'uptime_in_days':
    					$res['uptime_in_days'][$server]=$row;
    					break;
					case 'redis_version':
						$res['redis_version'][$server]=$row;
						break;
					case 'used_cpu_user':
						$res['used_cpu_user'][$server]=$row;
						break;
					case 'used_cpu_sys':
						$res['used_cpu_sys'][$server]=$row;
						break;
					case 'used_memory':
						$res['used_memory']+=$row;
						break;
    				case 'maxmemory':
    					$res['maxmemory']+=$row;
    					break;
    				case 'keyspace_hits':
    					$res['keyspace_hits']+=$row;
    					break;
        			case 'keyspace_misses':
        				$res['keyspace_misses']+=$row;
        				break;
					case 'connected_clients':
						$res['connected_clients']+=$row;
						break;
					case 'total_connections_received':
						$res['total_connections_received']+=$row;
						break;
    				case 'bgsave_in_progress':
    					$res['bgsave_in_progress']+=$row;
    					break;
				}
			}
		}
		return $res;
	}
	return $resp;
}

//////////////////////////////////////////////////////

//
// don't cache this page
//
header("Cache-Control: no-store, no-cache, must-revalidate");  // HTTP/1.1
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");                                    // HTTP/1.0

function duration($ts) {
    global $time;
    $years = (int)((($time - $ts)/(7*86400))/52.177457);
    $rem = (int)(($time-$ts)-($years * 52.177457 * 7 * 86400));
    $weeks = (int)(($rem)/(7*86400));
    $days = (int)(($rem)/86400) - $weeks*7;
    $hours = (int)(($rem)/3600) - $days*24 - $weeks*7*24;
    $mins = (int)(($rem)/60) - $hours*60 - $days*24*60 - $weeks*7*24*60;
    $str = '';
    if($years==1) $str .= "$years year, ";
    if($years>1) $str .= "$years years, ";
    if($weeks==1) $str .= "$weeks week, ";
    if($weeks>1) $str .= "$weeks weeks, ";
    if($days==1) $str .= "$days day,";
    if($days>1) $str .= "$days days,";
    if($hours == 1) $str .= " $hours hour and";
    if($hours>1) $str .= " $hours hours and";
    if($mins == 1) $str .= " 1 minute";
    else $str .= " $mins minutes";
    return $str;
}

// create graphics
//
function graphics_avail() {
	return extension_loaded('gd');
}

function bsize($s) {
	foreach (array('','K','M','G') as $i => $k) {
		if ($s < 1024) break;
		$s/=1024;
	}
	return sprintf("%5.1f %sBytes",$s,$k);
}

// create menu entry
function menu_entry($ob,$title) {
	global $PHP_SELF;
	if ($ob==$_GET['op']){
	    return "<li><a class=\"child_active\" href=\"$PHP_SELF&op=$ob\">$title</a></li>";
	}
	return "<li><a class=\"active\" href=\"$PHP_SELF&op=$ob\">$title</a></li>";
}

function getHeader(){
    $header = <<<EOB
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head><title>Redis INFO</title>
<style type="text/css"><!--
body { background:white; font-size:100.01%; margin:0; padding:0; }
body,p,td,th,input,submit { font-size:0.8em;font-family:arial,helvetica,sans-serif; }
* html body   {font-size:0.8em}
* html p      {font-size:0.8em}
* html td     {font-size:0.8em}
* html th     {font-size:0.8em}
* html input  {font-size:0.8em}
* html submit {font-size:0.8em}
td { vertical-align:top }
a { color:black; font-weight:none; text-decoration:none; }
a:hover { text-decoration:underline; }
div.content { padding:1em 1em 1em 1em; position:absolute; width:97%; z-index:100; }

h1.Redis { background:rgb(153,153,204); margin:0; padding:0.5em 1em 0.5em 1em; }
* html h1.Redis { margin-bottom:-7px; }
h1.Redis a:hover { text-decoration:none; color:rgb(90,90,90); }
h1.Redis span.logo {
	background:rgb(119,123,180);
	color:black;
	border-right: solid black 1px;
	border-bottom: solid black 1px;
	font-style:italic;
	font-size:1em;
	padding-left:1.2em;
	padding-right:1.2em;
	text-align:right;
	display:block;
	width:130px;
	}
h1.Redis span.logo span.name { color:white; font-size:0.7em; padding:0 0.8em 0 2em; }
h1.Redis span.nameinfo { color:white; display:inline; font-size:0.4em; margin-left: 3em; }
h1.Redis div.copy { color:black; font-size:0.4em; position:absolute; right:1em; }
hr.Redis {
	background:white;
	border-bottom:solid rgb(102,102,153) 1px;
	border-style:none;
	border-top:solid rgb(102,102,153) 10px;
	height:12px;
	margin:0;
	margin-top:1px;
	padding:0;
}

ol,menu { margin:1em 0 0 0; padding:0.2em; margin-left:1em;}
ol.menu li { display:inline; margin-right:0.7em; list-style:none; font-size:85%}
ol.menu a {
	background:rgb(153,153,204);
	border:solid rgb(102,102,153) 2px;
	color:white;
	font-weight:bold;
	margin-right:0em;
	padding:0.1em 0.5em 0.1em 0.5em;
	text-decoration:none;
	margin-left: 5px;
	}
ol.menu a.child_active {
	background:rgb(153,153,204);
	border:solid rgb(102,102,153) 2px;
	color:white;
	font-weight:bold;
	margin-right:0em;
	padding:0.1em 0.5em 0.1em 0.5em;
	text-decoration:none;
	border-left: solid black 5px;
	margin-left: 0px;
	}
ol.menu span.active {
	background:rgb(153,153,204);
	border:solid rgb(102,102,153) 2px;
	color:black;
	font-weight:bold;
	margin-right:0em;
	padding:0.1em 0.5em 0.1em 0.5em;
	text-decoration:none;
	border-left: solid black 5px;
	}
ol.menu span.inactive {
	background:rgb(193,193,244);
	border:solid rgb(182,182,233) 2px;
	color:white;
	font-weight:bold;
	margin-right:0em;
	padding:0.1em 0.5em 0.1em 0.5em;
	text-decoration:none;
	margin-left: 5px;
	}
ol.menu a:hover {
	background:rgb(193,193,244);
	text-decoration:none;
	}


div.info {
	background:rgb(204,204,204);
	border:solid rgb(204,204,204) 1px;
	margin-bottom:1em;
	}
div.info h2 {
	background:rgb(204,204,204);
	color:black;
	font-size:1em;
	margin:0;
	padding:0.1em 1em 0.1em 1em;
	}
div.info table {
	border:solid rgb(204,204,204) 1px;
	border-spacing:0;
	width:100%;
	}
div.info table th {
	background:rgb(204,204,204);
	color:white;
	margin:0;
	padding:0.1em 1em 0.1em 1em;
	}
div.info table th a.sortable { color:black; }
div.info table tr.tr-0 { background:rgb(238,238,238); }
div.info table tr.tr-1 { background:rgb(221,221,221); }
div.info table td { padding:0.3em 1em 0.3em 1em; }
div.info table td.td-0 { border-right:solid rgb(102,102,153) 1px; white-space:nowrap; }
div.info table td.td-n { border-right:solid rgb(102,102,153) 1px; }
div.info table td h3 {
	color:black;
	font-size:1.1em;
	margin-left:-0.3em;
	}
.td-0 a , .td-n a, .tr-0 a , tr-1 a {
    text-decoration:underline;
}
div.graph { margin-bottom:1em }
div.graph h2 { background:rgb(204,204,204);; color:black; font-size:1em; margin:0; padding:0.1em 1em 0.1em 1em; }
div.graph table { border:solid rgb(204,204,204) 1px; color:black; font-weight:normal; width:100%; }
div.graph table td.td-0 { background:rgb(238,238,238); }
div.graph table td.td-1 { background:rgb(221,221,221); }
div.graph table td { padding:0.2em 1em 0.4em 1em; }

div.div1,div.div2 { margin-bottom:1em; width:35em; }
div.div3 { position:absolute; left:40em; top:1em; width:580px; }
//div.div3 { position:absolute; left:37em; top:1em; right:1em; }

div.sorting { margin:1.5em 0em 1.5em 2em }
.center { text-align:center }
.aright { position:absolute;right:1em }
.right { text-align:right }
.ok { color:rgb(0,200,0); font-weight:bold}
.failed { color:rgb(200,0,0); font-weight:bold}

span.box {
	border: black solid 1px;
	border-right:solid black 2px;
	border-bottom:solid black 2px;
	padding:0 0.5em 0 0.5em;
	margin-right:1em;
}
span.green { background:#60F060; padding:0 0.5em 0 0.5em}
span.red { background:#D06030; padding:0 0.5em 0 0.5em }

div.authneeded {
	background:rgb(238,238,238);
	border:solid rgb(204,204,204) 1px;
	color:rgb(200,0,0);
	font-size:1.2em;
	font-weight:bold;
	padding:2em;
	text-align:center;
	}

input {
	background:rgb(153,153,204);
	border:solid rgb(102,102,153) 2px;
	color:white;
	font-weight:bold;
	margin-right:1em;
	padding:0.1em 0.5em 0.1em 0.5em;
	}
//-->
</style>
</head>
<body>
<div class="head">
	<h1 class="Redis">
		<span class="logo">Redis</span>
		<span class="nameinfo">Redismon.php by David</span>
	</h1>
	<hr class="Redis">
</div>
<div class=content>
EOB;

    return $header;
}
function getFooter(){
    global $VERSION;
    $footer = '</div><!-- Based on apc.php '.$VERSION.'--></body>
</html>
';

    return $footer;

}
function getMenu(){
    global $PHP_SELF;
echo "<ol class=menu>";
if ($_GET['op']!=4){
echo <<<EOB
    <li><a href="$PHP_SELF&op={$_GET['op']}">Refresh Data</a></li>
EOB;
}
else {
echo <<<EOB
    <li><a href="$PHP_SELF&op=2}">Back</a></li>
EOB;
}
/*
echo
	menu_entry(1,'View Host Stats'),
	menu_entry(2,'Variables');
*/
echo <<<EOB
	</ol>
	<br/>
EOB;
}

// TODO, AUTH

$_GET['op'] = !isset($_GET['op'])? '1':$_GET['op'];
$PHP_SELF= isset($_SERVER['PHP_SELF']) ? htmlentities(strip_tags($_SERVER['PHP_SELF'],'')) : '';

$PHP_SELF=$PHP_SELF.'?';
$time = time();
// sanitize _GET

foreach($_GET as $key=>$g){
    $_GET[$key]=htmlentities($g);
}


// singleout
// when singleout is set, it only gives details for that server.
if (isset($_GET['singleout']) && $_GET['singleout']>=0 && $_GET['singleout'] <count($REDIS_SERVERS)){
    $REDIS_SERVERS = array($REDIS_SERVERS[$_GET['singleout']]);
}

// display images
if (isset($_GET['IMG'])){
    $RedisStats = getRedisStats();
    $RedisStatsSingle = getRedisStats(false);

    if (!graphics_avail()) {
		exit(0);
	}

	function fill_box($im, $x, $y, $w, $h, $color1, $color2,$text='',$placeindex='') {
		global $col_black;
		$x1=$x+$w-1;
		$y1=$y+$h-1;

		imagerectangle($im, $x, $y1, $x1+1, $y+1, $col_black);
		if($y1>$y) imagefilledrectangle($im, $x, $y, $x1, $y1, $color2);
		else imagefilledrectangle($im, $x, $y1, $x1, $y, $color2);
		imagerectangle($im, $x, $y1, $x1, $y, $color1);
		if ($text) {
			if ($placeindex>0) {

				if ($placeindex<16)
				{
					$px=5;
					$py=$placeindex*12+6;
					imagefilledrectangle($im, $px+90, $py+3, $px+90-4, $py-3, $color2);
					imageline($im,$x,$y+$h/2,$px+90,$py,$color2);
					imagestring($im,2,$px,$py-6,$text,$color1);

				} else {
					if ($placeindex<31) {
						$px=$x+40*2;
						$py=($placeindex-15)*12+6;
					} else {
						$px=$x+40*2+100*intval(($placeindex-15)/15);
						$py=($placeindex%15)*12+6;
					}
					imagefilledrectangle($im, $px, $py+3, $px-4, $py-3, $color2);
					imageline($im,$x+$w,$y+$h/2,$px,$py,$color2);
					imagestring($im,2,$px+2,$py-6,$text,$color1);
				}
			} else {
				imagestring($im,4,$x+5,$y1-16,$text,$color1);
			}
		}
	}


    function fill_arc($im, $centerX, $centerY, $diameter, $start, $end, $color1,$color2,$text='',$placeindex=0) {
		$r=$diameter/2;
		$w=deg2rad((360+$start+($end-$start)/2)%360);


		if (function_exists("imagefilledarc")) {
			// exists only if GD 2.0.1 is avaliable
			imagefilledarc($im, $centerX+1, $centerY+1, $diameter, $diameter, $start, $end, $color1, IMG_ARC_PIE);
			imagefilledarc($im, $centerX, $centerY, $diameter, $diameter, $start, $end, $color2, IMG_ARC_PIE);
			imagefilledarc($im, $centerX, $centerY, $diameter, $diameter, $start, $end, $color1, IMG_ARC_NOFILL|IMG_ARC_EDGED);
		} else {
			imagearc($im, $centerX, $centerY, $diameter, $diameter, $start, $end, $color2);
			imageline($im, $centerX, $centerY, $centerX + cos(deg2rad($start)) * $r, $centerY + sin(deg2rad($start)) * $r, $color2);
			imageline($im, $centerX, $centerY, $centerX + cos(deg2rad($start+1)) * $r, $centerY + sin(deg2rad($start)) * $r, $color2);
			imageline($im, $centerX, $centerY, $centerX + cos(deg2rad($end-1))   * $r, $centerY + sin(deg2rad($end))   * $r, $color2);
			imageline($im, $centerX, $centerY, $centerX + cos(deg2rad($end))   * $r, $centerY + sin(deg2rad($end))   * $r, $color2);
			imagefill($im,$centerX + $r*cos($w)/2, $centerY + $r*sin($w)/2, $color2);
		}
		if ($text) {
			if ($placeindex>0) {
				imageline($im,$centerX + $r*cos($w)/2, $centerY + $r*sin($w)/2,$diameter, $placeindex*12,$color1);
				imagestring($im,4,$diameter, $placeindex*12,$text,$color1);

			} else {
				imagestring($im,4,$centerX + $r*cos($w)/2, $centerY + $r*sin($w)/2,$text,$color1);
			}
		}
	}
	$size = GRAPH_SIZE; // image size
	$image = imagecreate($size+50, $size+10);

	$col_white = imagecolorallocate($image, 0xFF, 0xFF, 0xFF);
	$col_red   = imagecolorallocate($image, 0xD0, 0x60,  0x30);
	$col_green = imagecolorallocate($image, 0x60, 0xF0, 0x60);
	$col_black = imagecolorallocate($image,   0,   0,   0);

	imagecolortransparent($image,$col_white);

    switch ($_GET['IMG']){
        case 1: // pie chart
            $tsize=$RedisStats['maxmemory'];
    		$avail=$tsize-$RedisStats['used_memory'];
    		$x=$y=$size/2;
    		$angle_from = 0;
    		$fuzz = 0.000001;

            foreach($RedisStatsSingle as $serv=>$mcs) {
    			$free = $mcs['maxmemory']-$mcs['used_memory'];
    			$used = $mcs['used_memory'];


                if ($free>0){
    			// draw free
    			    $angle_to = ($free*360)/$tsize;
                    $perc =sprintf("%.2f%%", ($free *100) / $tsize) ;

        			fill_arc($image,$x,$y,$size,$angle_from,$angle_from + $angle_to ,$col_black,$col_green,$perc);
        			$angle_from = $angle_from + $angle_to ;
                }
    			if ($used>0){
    			// draw used
        			$angle_to = ($used*360)/$tsize;
        			$perc =sprintf("%.2f%%", ($used *100) / $tsize) ;
        			fill_arc($image,$x,$y,$size,$angle_from,$angle_from + $angle_to ,$col_black,$col_red, '('.$perc.')' );
                    $angle_from = $angle_from+ $angle_to ;
    			}
    			}

        break;

        case 2: // hit miss

            $hits = ($RedisStats['keyspace_hits']==0) ? 1:$RedisStats['keyspace_hits'];
            $misses = ($RedisStats['keyspace_misses']==0) ? 1:$RedisStats['keyspace_misses'];
            $total = $hits + $misses ;

	       	fill_box($image, 30,$size,50,-$hits*($size-21)/$total,$col_black,$col_green,sprintf("%.1f%%",$hits*100/$total));
		    fill_box($image,130,$size,50,-max(4,($total-$hits)*($size-21)/$total),$col_black,$col_red,sprintf("%.1f%%",$misses*100/$total));
		break;
		
    }
    header("Content-type: image/png");
	imagepng($image);
	exit;
}

echo getHeader();
echo getMenu();

switch ($_GET['op']) {

    case 1: // host stats
    	$phpversion = phpversion();
        $RedisStats = getRedisStats();
        $RedisStatsSingle = getRedisStats(false);

        $mem_size = $RedisStats['maxmemory'];
    	$mem_used = $RedisStats['used_memory'];
	    $mem_avail= $mem_size-$mem_used;
	    $startTime = time()-array_sum($RedisStats['uptime_in_seconds']);
	    
        $hits = ($RedisStats['keyspace_hits']==0) ? 1:$RedisStats['keyspace_hits'];
        $misses = ($RedisStats['keyspace_misses']==0) ? 1:$RedisStats['keyspace_misses'];

       	$req_rate = sprintf("%.2f",($hits+$misses)/($time-$startTime));
	    $hit_rate = sprintf("%.2f",($hits)/($time-$startTime));
	    $miss_rate = sprintf("%.2f",($misses)/($time-$startTime));

	    echo <<< EOB
		<div class="info div1"><h2>General Cache Information</h2>
		<table cellspacing=0><tbody>
		<tr class=tr-1><td class=td-0>PHP Version</td><td>$phpversion</td></tr>
EOB;
		echo "<tr class=tr-0><td class=td-0>Redis Host". ((count($REDIS_SERVERS)>1) ? 's':'')."</td><td>";
		$i=0;
		if (!isset($_GET['singleout']) && count($REDIS_SERVERS)>1){
    		foreach($REDIS_SERVERS as $server){
    		      echo ($i+1).'. <a href="'.$PHP_SELF.'&singleout='.$i++.'">'.$server.'</a><br/>';
    		}
		}
		else{
		    echo '1.'.$REDIS_SERVERS[0];
		}
		if (isset($_GET['singleout'])){
		      echo '<a href="'.$PHP_SELF.'">(all servers)</a><br/>';
		}
		echo "</td></tr>\n";
		echo "<tr class=tr-1><td class=td-0>Total Redis Cache</td><td>".bsize($RedisStats['maxmemory'])."</td></tr>\n";

	echo <<<EOB
		</tbody></table>
		</div>

		<div class="info div1"><h2>Redis Server Information</h2>
EOB;
        foreach($REDIS_SERVERS as $server){
            echo '<table cellspacing=0><tbody>';
            echo '<tr class=tr-1><td class=td-1>'.$server.'</td><td></td></tr>';
    		echo '<tr class=tr-0><td class=td-0>Uptime days</td><td>',$RedisStatsSingle[$server]['uptime_in_days'] ,'days</td></tr>';
    		echo '<tr class=tr-0><td class=td-0>Last_save_time </td><td>',date(DATE_FORMAT,intval($RedisStatsSingle[$server]['last_save_time'])) ,'</td></tr>';
    		
    		echo '<tr class=tr-0><td class=td-0>Redis Server Version</td><td>'.$RedisStatsSingle[$server]['redis_version'].'</td></tr>';
    		echo '<tr class=tr-1><td class=td-0>Used Cache Size</td><td>',$RedisStatsSingle[$server]['used_memory_human'],'</td></tr>';
    		echo '<tr class=tr-0><td class=td-0>Total Cache Size</td><td>',$RedisStatsSingle[$server]['maxmemory'],'</td></tr>';
    		echo '</tbody></table>';
	   }
    echo <<<EOB

		</div>
		<div class="graph div3"><h2>Host Status Diagrams</h2>
		<table cellspacing=0><tbody>
EOB;

	$size='width='.(GRAPH_SIZE+50).' height='.(GRAPH_SIZE+10);
	echo <<<EOB
		<tr>
		<td class=td-0>Cache Usage</td>
		<td class=td-1>Hits &amp; Misses</td>
		</tr>
EOB;

	echo
		graphics_avail() ?
			  '<tr>'.
			  "<td class=td-0><img alt=\"\" $size src=\"$PHP_SELF&IMG=1&".(isset($_GET['singleout'])? 'singleout='.$_GET['singleout'].'&':'')."$time\"></td>".
			  "<td class=td-1><img alt=\"\" $size src=\"$PHP_SELF&IMG=2&".(isset($_GET['singleout'])? 'singleout='.$_GET['singleout'].'&':'')."$time\"></td></tr>\n"
			: "",
		'<tr>',
		'<td class=td-0><span class="green box">&nbsp;</span>Free: ',bsize($mem_avail).sprintf(" (%.1f%%)",$mem_avail*100/$mem_size),"</td>\n",
		'<td class=td-1><span class="green box">&nbsp;</span>Hits: ',$hits.sprintf(" (%.1f%%)",$hits*100/($hits+$misses)),"</td>\n",
		'</tr>',
		'<tr>',
		'<td class=td-0><span class="red box">&nbsp;</span>Used: ',bsize($mem_used ).sprintf(" (%.1f%%)",$mem_used *100/$mem_size),"</td>\n",
		'<td class=td-1><span class="red box">&nbsp;</span>Misses: ',$misses.sprintf(" (%.1f%%)",$misses*100/($hits+$misses)),"</td>\n";
		echo <<< EOB
	</tr>
	</tbody></table>
<br/>
	<div class="info"><h2>Cache Information</h2>
		<table cellspacing=0><tbody>
		<tr class=tr-1><td class=td-0>Hits</td><td>{$hits}</td></tr>
		<tr class=tr-0><td class=td-0>Misses</td><td>{$misses}</td></tr>
		<tr class=tr-1><td class=td-0>Request Rate (hits, misses)</td><td>$req_rate cache requests/second</td></tr>
		<tr class=tr-0><td class=td-0>Hit Rate</td><td>$hit_rate cache requests/second</td></tr>
		<tr class=tr-1><td class=td-0>Miss Rate</td><td>$miss_rate cache requests/second</td></tr>
		</tbody></table>
		</div>

EOB;

    break;
}
echo getFooter();

?>