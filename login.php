<?php
include("./includes/common.php");

if(!$conf['userlogin']){
    @header('Content-Type: text/html; charset=UTF-8');
	exit("<script language='javascript'>alert('未开启登录');window.location.href='./';</script>");
}

function bind_user_files($uid){
    global $DB;
    if(isset($_SESSION['fileids']) && count($_SESSION['fileids'])>0){
        $ids = array_reverse($_SESSION['fileids']);
        if(count($ids) > 60){
            $ids = array_splice($ids, 0, 60);
        }
        $ids = implode(',', array_map('intval', $ids));
        if($ids){
            $DB->exec("UPDATE pre_file SET uid='{$uid}' WHERE id IN ({$ids}) AND uid=0");
        }
    }
}

function set_user_login($uid, $type, $openid){
    global $password_hash;
    bind_user_files($uid);
    $session=md5($type.$openid.$password_hash);
    $expiretime=time()+2592000;
    $token=authcode("{$uid}\t{$session}\t{$expiretime}", 'ENCODE', SYS_KEY);
    setcookie("user_token", $token, time() + 2592000, '/');
}

function check_account_name($username){
    return preg_match('/^[A-Za-z0-9_@.-]{3,32}$/', $username);
}

if(isset($_GET['logout'])){
	if(!checkRefererHost())exit();
	setcookie("user_token", "", time() - 1, '/');
	@header('Content-Type: text/html; charset=UTF-8');
	exit("<script language='javascript'>alert('您已成功注销本次登录！');window.location.href='./login.php';</script>");
}elseif($islogin2==1){
	@header('Content-Type: text/html; charset=UTF-8');
	exit("<script language='javascript'>alert('您已登录！');window.location.href='./';</script>");
}elseif(isset($_GET['act']) && $_GET['act']=='account_login'){
    @header('Content-Type: application/json; charset=UTF-8');
    if(!$conf['account_login'])exit('{"code":-1,"msg":"未开启账号密码登录"}');
    $username = isset($_POST['username'])?trim($_POST['username']):'';
    $password = isset($_POST['password'])?$_POST['password']:'';
    if(!check_account_name($username))exit('{"code":-1,"msg":"账号需为3-32位字母、数字、下划线、点、横线或@符号"}');
    if(strlen($password)<6 || strlen($password)>64)exit('{"code":-1,"msg":"密码长度需为6-64位"}');
    $userrow=$DB->find('user','*',['type'=>'account', 'openid'=>$username], null, '1');
    if(!$userrow || !$userrow['password'] || !password_verify($password, $userrow['password'])){
        exit('{"code":-1,"msg":"账号或密码错误"}');
    }
    if($userrow['enable']==0){
        exit('{"code":-1,"msg":"当前用户已被禁止登录"}');
    }
    $uid = $userrow['uid'];
    $DB->update('user', ['loginip' => $clientip, 'lasttime'=>'NOW()'], ['uid'=>$uid]);
    set_user_login($uid, 'account', $username);
    exit('{"code":0,"msg":"登录成功","url":"./"}');
}elseif(isset($_GET['act']) && $_GET['act']=='account_register'){
    @header('Content-Type: application/json; charset=UTF-8');
    if(!$conf['account_register'])exit('{"code":-1,"msg":"未开启邀请码注册"}');
    $invite_code = trim($conf['invite_code']);
    if($invite_code==='')exit('{"code":-1,"msg":"管理员未配置注册邀请码"}');
    $username = isset($_POST['username'])?trim($_POST['username']):'';
    $password = isset($_POST['password'])?$_POST['password']:'';
    $password2 = isset($_POST['password2'])?$_POST['password2']:'';
    $invite = isset($_POST['invite'])?trim($_POST['invite']):'';
    if(!check_account_name($username))exit('{"code":-1,"msg":"账号需为3-32位字母、数字、下划线、点、横线或@符号"}');
    if(strlen($password)<6 || strlen($password)>64)exit('{"code":-1,"msg":"密码长度需为6-64位"}');
    if($password!==$password2)exit('{"code":-1,"msg":"两次输入的密码不一致"}');
    if($invite!==$invite_code)exit('{"code":-1,"msg":"邀请码错误"}');
    if($DB->find('user','uid',['type'=>'account', 'openid'=>$username], null, '1')){
        exit('{"code":-1,"msg":"该账号已被注册"}');
    }
    $uid = $DB->insert('user', [
        'type' => 'account',
        'openid' => $username,
        'nickname' => $username,
        'faceimg' => '',
        'password' => password_hash($password, PASSWORD_DEFAULT),
        'enable' => 1,
        'regip' => $clientip,
        'loginip' => $clientip,
        'addtime' => 'NOW()',
        'lasttime' => 'NOW()',
    ]);
    if(!$uid)exit('{"code":-1,"msg":"用户注册失败 '.$DB->error().'"}');
    set_user_login($uid, 'account', $username);
    exit('{"code":0,"msg":"注册成功","url":"./"}');
}elseif(isset($_GET['act']) && $_GET['act']=='connect'){
    @header('Content-Type: application/json; charset=UTF-8');
    $type = isset($_POST['type'])?$_POST['type']:exit('{"code":-1,"msg":"no type"}');
    if(!$conf['login_apiurl'] || !$conf['login_appid'] || !$conf['login_appkey'])exit('{"code":-1,"msg":"未配置好快捷登录接口信息"}');
    $Oauth = new \lib\Oauth($conf['login_apiurl'], $conf['login_appid'], $conf['login_appkey']);
    $res = $Oauth->login($type);
    if(isset($res['code']) && $res['code']==0){
        $result = ['code'=>0, 'url'=>$res['url']];
    }elseif(isset($res['code'])){
        $result = ['code'=>-1, 'msg'=>$res['msg']];
    }else{
        $result = ['code'=>-1, 'msg'=>'快捷登录接口请求失败'];
    }
    exit(json_encode($result));
}elseif($_GET['code'] && $_GET['type'] && $_GET['state']){
	if($_GET['state'] != $_SESSION['Oauth_state']){
		sysmsg("<h2>The state does not match. You may be a victim of CSRF.</h2>");
	}
	$type = $_GET['type'];
    $typename = $type=='wx'?'微信':'QQ';
	$Oauth = new \lib\Oauth($conf['login_apiurl'], $conf['login_appid'], $conf['login_appkey']);
	$arr = $Oauth->callback();
	if(isset($arr['code']) && $arr['code']==0){
		$openid=$arr['social_uid'];
		$access_token=$arr['access_token'];
		$nickname=trim($arr['nickname']);
        if(empty($nickname) || $nickname=='-') $nickname = $typename.'用户';
		$faceimg=$arr['faceimg'];
	}elseif(isset($arr['code'])){
		sysmsg('<h3>error:</h3>'.$arr['errcode'].'<h3>msg  :</h3>'.$arr['msg']);
	}else{
		sysmsg('获取登录数据失败');
	}

    $userrow=$DB->find('user','*',['type'=>$type, 'openid'=>$openid], null, '1');
	if(!$userrow){
        if(!$DB->insert('user', [
            'type' => $type,
            'openid' => $openid,
            'nickname' => $nickname,
            'faceimg' => $faceimg,
            'enable' => 1,
            'regip' => $clientip,
            'loginip' => $clientip,
            'addtime' => 'NOW()',
            'lasttime' => 'NOW()',
        ]))sysmsg('用户注册失败 '.$DB->error());
        $uid = $DB->lastInsertId();
	}else{
        if($userrow['enable']==0){
            $_SESSION['user_block'] = true;
            sysmsg('当前用户已被禁止登录');
        }
        $uid = $userrow['uid'];
        $DB->update('user', ['loginip' => $clientip, 'lasttime'=>'NOW()'], ['uid'=>$uid]);
    }
    if($_SESSION['user_block']){
        $DB->update('user', ['enable' => 0], ['uid'=>$uid]);
        sysmsg('当前用户已被禁止登录');
    }
    set_user_login($uid, $type, $openid);
    ob_clean();
    exit("<script language='javascript'>window.location.href='./';</script>");
}

$title = '用户登录 - ' . $conf['title'];
include SYSTEM_ROOT.'header.php';
?>
<div class="container">
<div class="col-xs-12 col-sm-10 col-md-8 col-lg-6 center-block" style="float: none;">
    <div class="well bs-component" style="margin-top:80px">
        <ul class="nav nav-tabs" style="margin-bottom: 20px;">
            <?php if($conf['account_login']){?><li class="active"><a href="#account_login" data-toggle="tab">账号登录</a></li><?php }?>
            <?php if($conf['account_register']){?><li class="<?php echo !$conf['account_login']?'active':null;?>"><a href="#account_register" data-toggle="tab">邀请码注册</a></li><?php }?>
            <li class="<?php echo !$conf['account_login']&&!$conf['account_register']?'active':null;?>"><a href="#quick_login" data-toggle="tab">快捷登录</a></li>
        </ul>
        <div class="tab-content">
            <?php if($conf['account_login']){?>
            <div class="tab-pane active" id="account_login">
                <form onsubmit="return accountLogin()" class="form-horizontal">
                    <div class="form-group">
                        <label class="col-sm-3 control-label">账号</label>
                        <div class="col-sm-9"><input type="text" name="username" class="form-control" autocomplete="username" placeholder="请输入账号"/></div>
                    </div>
                    <div class="form-group">
                        <label class="col-sm-3 control-label">密码</label>
                        <div class="col-sm-9"><input type="password" name="password" class="form-control" autocomplete="current-password" placeholder="请输入密码"/></div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-offset-3 col-sm-9"><button type="submit" class="btn btn-primary btn-block">登录</button></div>
                    </div>
                </form>
            </div>
            <?php }?>
            <?php if($conf['account_register']){?>
            <div class="tab-pane <?php echo !$conf['account_login']?'active':null;?>" id="account_register">
                <form onsubmit="return accountRegister()" class="form-horizontal">
                    <div class="form-group">
                        <label class="col-sm-3 control-label">账号</label>
                        <div class="col-sm-9"><input type="text" name="username" class="form-control" autocomplete="username" placeholder="3-32位字母、数字、_ . - @"/></div>
                    </div>
                    <div class="form-group">
                        <label class="col-sm-3 control-label">密码</label>
                        <div class="col-sm-9"><input type="password" name="password" class="form-control" autocomplete="new-password" placeholder="6-64位密码"/></div>
                    </div>
                    <div class="form-group">
                        <label class="col-sm-3 control-label">确认密码</label>
                        <div class="col-sm-9"><input type="password" name="password2" class="form-control" autocomplete="new-password" placeholder="请再次输入密码"/></div>
                    </div>
                    <div class="form-group">
                        <label class="col-sm-3 control-label">邀请码</label>
                        <div class="col-sm-9"><input type="text" name="invite" class="form-control" placeholder="请输入邀请码"/></div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-offset-3 col-sm-9"><button type="submit" class="btn btn-success btn-block">注册并登录</button></div>
                    </div>
                </form>
            </div>
            <?php }?>
            <div class="tab-pane <?php echo !$conf['account_login']&&!$conf['account_register']?'active':null;?>" id="quick_login">
                <div class="row text-center">
                <div class="col-xs-12">
                    <h5>请选择登录方式</h5><br/>
                    <p id="loginform">
                        <?php if($conf['login_qq']){?><a href="javascript:connect('qq')" class="btn btn-info btn-fab loginbtn"><i class="fa fa-qq"></i></a><?php }?>
                        <?php if($conf['login_wx']){?><a href="javascript:connect('wx')" class="btn btn-success btn-fab loginbtn"><i class="fa fa-wechat"></i></a><?php }?>
                    </p>
                    <p class="text-muted">新用户快捷登录后会自动注册账号</p>
                </div>
                </div>
            </div>
        </div>
    </div>
</div>
</div>
<?php include SYSTEM_ROOT.'footer.php';?>
<script src="https://s4.zstatic.net/ajax/libs/layer/2.3/layer.js"></script>
<script>
function connect(type){
    var ii = layer.load(2, {shade:[0.1,'#fff']});
	$.ajax({
		type : "POST",
		url : "login.php?act=connect",
		data : {type:type},
		dataType : 'json',
		success : function(data) {
			layer.close(ii);
			if(data.code == 0){
				window.location.href = data.url;
			}else{
				layer.alert(data.msg, {icon: 7});
			}
		} 
	});
}
function accountLogin(){
    var ii = layer.load(2, {shade:[0.1,'#fff']});
    $.ajax({
        type : "POST",
        url : "login.php?act=account_login",
        data : $("#account_login form").serialize(),
        dataType : 'json',
        success : function(data) {
            layer.close(ii);
            if(data.code == 0){
                window.location.href = data.url;
            }else{
                layer.alert(data.msg, {icon: 7});
            }
        },
        error:function(){
            layer.close(ii);
            layer.alert('服务器错误', {icon: 7});
        }
    });
    return false;
}
function accountRegister(){
    var ii = layer.load(2, {shade:[0.1,'#fff']});
    $.ajax({
        type : "POST",
        url : "login.php?act=account_register",
        data : $("#account_register form").serialize(),
        dataType : 'json',
        success : function(data) {
            layer.close(ii);
            if(data.code == 0){
                window.location.href = data.url;
            }else{
                layer.alert(data.msg, {icon: 7});
            }
        },
        error:function(){
            layer.close(ii);
            layer.alert('服务器错误', {icon: 7});
        }
    });
    return false;
}
</script>
</body>
</html>
