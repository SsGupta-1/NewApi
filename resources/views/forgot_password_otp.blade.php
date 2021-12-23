<?php
/**
 * Views File Doc Comment
 *
 * PHP Version 5
 *
 * @category Views
 * @package  Views
 * @license  http://quytech.com/ 
 * @link     application/views
 */
?>
<!DOCTYPE html>
<html>
   <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
   </head>
   <body style="margin:0;">
      <table valign="middle" cellspacing="0" cellpadding="0" style="max-width:600px;text-align:center;width:100%; font-family: arial; font-size: 14px;vertical-align: middle; color:#373536;margin:0 auto 15px;background:#fff url(header-img.png) no-repeat center top;border:1px solid #eee">
         <tbody>
            
            
            <tr>
               <td align="center">
                  <div>
                     <h1 style="font-family: Comic Sans MS;color: #206dac; margin-top: 0">Hello {{ $email }}</h1>
										 <h2>Otp {{$otp}}</h2>
                  </div>
               </td>
            </tr>
            <tr>
               <td align="center" style="color:#555;font-size:16px;line-height:25px; font-family: Comic Sans MS">
                  <p style="font-size:16px; padding: 0 15px; margin: 0">You are receiving this email because we received a password reset request for your account.</p>
               </td>
						</tr>
						<tr><td align="enter"><p style="background:#206dac; color: #fff; padding: 15px 0; margin: 35px 0 0">Powered by Team</p></td></tr>            
         </tbody>
      </table>
   </body>
</html>
