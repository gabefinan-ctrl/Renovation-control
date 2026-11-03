import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
Deno.serve(async (req)=>{
  if(req.method==='OPTIONS') return new Response('ok',{headers:cors});
  try{
    const authHeader=req.headers.get('Authorization');
    if(!authHeader) throw new Error('Missing authorization');
    const admin=createClient(Deno.env.get('SUPABASE_URL')!,Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
    const token=authHeader.replace('Bearer ','');
    const {data:{user},error:userError}=await admin.auth.getUser(token);
    if(userError||!user) throw new Error('Not authenticated');
    const {email,role}=await req.json();
    const cleanEmail=String(email||'').trim().toLowerCase();
    const allowed=['project_manager','site_manager','purchasing','tradesperson','customer'];
    if(!cleanEmail||!cleanEmail.includes('@')) throw new Error('Enter a valid email');
    if(!allowed.includes(role)) throw new Error('Invalid role');
    const {data:membership}=await admin.from('memberships').select('company_id,role').eq('user_id',user.id).limit(1).single();
    if(!membership||membership.role!=='owner') throw new Error('Owner access required');
    const {data:existing}=await admin.from('memberships').select('id').eq('company_id',membership.company_id).eq('user_id', (await admin.auth.admin.listUsers()).data.users.find((u:any)=>u.email?.toLowerCase()===cleanEmail)?.id||'00000000-0000-0000-0000-000000000000').maybeSingle();
    if(existing) throw new Error('That user is already a member');
    const {data:invite,error:inviteError}=await admin.from('invitations').insert({company_id:membership.company_id,email:cleanEmail,role,invited_by:user.id}).select().single();
    if(inviteError) throw new Error(inviteError.code==='23505'?'An invitation for that email is already pending':inviteError.message);
    const {error:sendError}=await admin.auth.admin.inviteUserByEmail(cleanEmail,{data:{full_name:cleanEmail.split('@')[0]}});
    if(sendError){await admin.from('invitations').update({status:'cancelled'}).eq('id',invite.id);throw new Error(sendError.message);}
    return new Response(JSON.stringify({ok:true}),{headers:{...cors,'Content-Type':'application/json'}});
  }catch(e){return new Response(JSON.stringify({error:e instanceof Error?e.message:'Invitation failed'}),{status:400,headers:{...cors,'Content-Type':'application/json'}})}
});
