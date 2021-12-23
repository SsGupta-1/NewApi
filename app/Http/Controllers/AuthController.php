<?php

namespace App\Http\Controllers;

use App\User;
use App\Otp;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Auth;
use Hash;
use Validator;
use Str;
use DB;
use Mail;

class AuthController extends Controller
{
    public function signup(Request $request){

        $rules = [
            'name' => 'required|regex:/(^([a-zA-z]+)(\d+)?$)/u',
            'phone' => 'required|min:11|numeric',
            'phone' => 'max:15|unique:users,phone',
            "email"=>'required|max:32|email|unique:users,email',
            'password' => 'required|string|min:4|confirmed'
        ];
        $validator = Validator::make($request->all(),$rules);

        if($validator->fails()){
            return response()->json($validator->errors()->first(),400); // 400 = Bad Request
        }

        $user = new User([
            'name' => $request->name,
            'phone' => $request->phone,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $user->save();
        $tokenResult = $user->createToken('my token');
        $token = $tokenResult->token;
        $token->save();
        return response()->json([ 
            'message' => 'Successfully created user!' ,
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer'
        ], 201);  


        
    }



    public function login(Request $request){

        if(Auth::check()==true){
            return response()->json([ 'message' => 'you are already login' ], 401);
        }
        else{

        $rules = [
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ];
        $validator = Validator::make($request->all(),$rules);

        if($validator->fails()){
            return response()->json($validator->errors(),400); // 400 = Bad Request
        }
        
            $credentials = request(['email', 'password']);
        if(!Auth::attempt($credentials))
            return response()->json([ 'message' => 'Unauthorized! Your Credentials not match' ], 401);

        $user = $request->user();
       
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->AddDays(2);
        $token->save();

        return response()->json([
            'message' => 'Successfully Login!',
          
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString()
            ]);

        }
        
    }



    public function logout(Request $request){

        // $rules = [
        //     'token' => 'required',
        // ];
        // $validator = Validator::make($request->all(),$rules);

        // if($validator->fails()){
        //     return response()->json($validator->errors(),400); // 400 = Bad Request
        // }

        $request->user()->token()->revoke();
        
        return response()->json([
            'message' => 'Successfully logged out',
            
            
        ]);
    }



                public function user(Request $request){

                    // return Auth::user();

                    return response()->json($request->user());
                }


    public function forget(Request $request){
        
        $email = $request->email;

        if(User::where('email',$email)->doesntExist()){

            return response([
                'message' => 'User Does not exist!',
            ],404);
        }

        
        //  $token = $email->createToken('my token')->accessToken;
        // $token = $tokenResult->token;
        // $token->save();
        $token = Str::random(10);

        try{
            DB::table('password_resets')->insert([
                'email'=> $email,
                'token' => $token,
            ]); 

        //     Mail::to($request->email)->send();
        // $notification = array(
        //     'message' => 'Thanks! We shall get back to you soon.', 
        //     'alert-type' => 'success'
        // );
           
        Mail::send('forgetmail', ['token' => $token,'email'=>$email] ,function($message) use ($email){
                $message->to($email);
                $message->subject('Reset your password | Link');

            });

            return response([
                'message' => 'Reset link sent Successfully!',
                'token' => $token,
            ],200);


        }catch(\Exception $exception){
            return response([
                'message' => $exception->getMessage(),
            ],404);

        }
        
    }


            public function resetpassword(Request $request){

                $rules = [
                    'token' => 'required',
                    'password' => 'required|string|confirmed',
                
                ];
                $validator = Validator::make($request->all(),$rules);
        
                if($validator->fails()){
                    return response()->json($validator->errors(),400); // 400 = Bad Request
                }

               
             $token = $request->token;

            $result = DB::table('password_resets')->where('token',$token)->first();

                if(!$result){
                    return response([
                        'message' => 'invalid token',

                    ],400);
                }

                $user = User::where('email',$result->email)->first();

                if(!$user){
                    return response([
                        'message ' => 'user doesn\'t exist!'
                    ],404);
                }
                $user->password = Hash::make($request->password);
                $user->save();
                return response([
                    'message ' => 'Password reset successfull'
                ],200);
                
            }

   public function changePassword(Request $request){

                $validator = Validator::make($request->all(), [ 
                    'old_password' => 'required', 
                    'password' => 'required', 
                    'confirm_password' => 'required|same:password', 
                  ]);
            
                if ($validator->fails()) { 
                     return response()->json(['message'=>$validator->errors()->first(),'status'=>400],400);  
                }
      
                $old_password = $request->get('old_password');
                $newPassword = $request->get('password');
                $confirm_password = $request->get('confirm_password');
      
                //$user=Auth::guard('api');

                $user= $request->user();

                //return response()->json($request->user());
      
              if ($user){
                  if (Hash::check($old_password, $user->password)) { 
      
                      $passwordUpdate =User::where('id',$user->id)->update(['password'=>Hash::make($newPassword)]) ;
                      if ($passwordUpdate ) {
      
                        return response([
                            'message ' => 'Password changed successfully.'
                        ],200);
                      
                      } else {
                        return response([
                            'message ' => 'Password not changed.'
                        ],404);
                     
                      }
                  }	else {
                      return response([
                        'message ' => 'Old Password does not match.'
                      ],404);
                  }
      
              }  else {
                    return response()->json(['message'=>'User does not authenticate','code'=>401],401);
              }
     }



     public function forgotpassword(Request $request){

        $validator = Validator::make($request->all(), [
          'email' => 'required',  
        ]);
  
        if($validator->fails()){
             return response()->json(['message'=>$validator->errors()->first(),'status'=>400],400);  
               }
          $email = $request->get('email');
          $users_data =User::where('email',$email)->first();
          if(!empty($users_data))
          {
          
              $data['otp'] = rand(1000, 9999);
              $otp=new Otp();
              $otp->otp= $data['otp'];
              $otp->user_id=$users_data->id;
              $otp->active=0;
                    $result['user_id']=$users_data->id;
                    $result['email']=$users_data->email;
                    $result['otp']=$data['otp'];
                    $response=$result;
              $data=['name'=>$users_data->name,'email'=>$users_data->email,'otp'=>$otp->otp];
             $view =  'forgot_password_otp';
              $subject = 'Reset Password';
           
               Mail::send($view, $data, function ($m) use ($data,$subject) {
                $m->from('sonu.sah@quytech.com', 'Team');
    
                $m->to($data['email'])->subject($subject.' | VerifyOTP');
            });
  
  
            if($otp->save())
            {
              
              return response([ 'message ' => 'An otp has been sent on your registered email .', ],200);
            }
            else
            {
              return response([ 'message ' => 'Something went wrong',],404);
            }
          }
          else
          {
            return response([ 'message ' => 'User does not exists',],404);
          }
      
      }



}





