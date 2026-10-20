/* =====================================================================
   Supabase 어댑터: 앱이 쓰던 claude.use("db"|"user"|"assets"|"downloads") 를
   Supabase(Auth + Postgres docs 테이블 + Storage)로 연결한다.
   ===================================================================== */
(function(){
  const C=window.DJ_CONFIG||{};
  if(!window.supabase){ document.addEventListener('DOMContentLoaded',()=>{ const d=document.createElement('div'); d.style.cssText='position:fixed;left:0;right:0;top:0;z-index:99;background:#C42339;color:#fff;padding:10px 16px;font:13px system-ui'; d.textContent='서버 라이브러리를 불러오지 못했어요. 네트워크를 확인하고 새로고침해 주세요.'; document.body.appendChild(d); }); return; }
  if(!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(C.SUPABASE_URL||'')){ document.addEventListener('DOMContentLoaded',()=>{ const d=document.createElement('div'); d.style.cssText='position:fixed;left:0;right:0;top:0;z-index:99;background:#1B5876;color:#fff;padding:10px 16px;font:13px system-ui'; d.textContent='config.js 에 Supabase Project URL과 anon 키를 넣어 주세요.'; document.body.appendChild(d); }); return; } const sb=window.supabase.createClient(C.SUPABASE_URL,C.SUPABASE_ANON_KEY,{auth:{persistSession:true,autoRefreshToken:true}});
  window.sb=sb;
  const err=(code,message)=>Object.assign(new Error(message||code),{code});
  const newId=()=>{ const A='abcdefghijklmnopqrstuvwxyz0123456789'; let s=''; const r=new Uint32Array(14); crypto.getRandomValues(r); for(const n of r) s+=A[n%A.length]; return s; };
  const mapErr=e=>{ const m=(e&&e.message)||''; const bw=m.match(/banned_word:([^\s"]+)/); if(bw) return err('banned',bw[1]); if(/invalid_argument|not allowed|row-level security|does not exist/i.test(m)) return err('invalid_argument',m); return err('unavailable',m); };

  /* ---------- 실시간 변경 → 리스너에게 알림 (컬렉션 단위) ---------- */
  const listeners=new Map(); // collection -> Set(fn)
  let chan=null;
  function ensureChannel(){ if(chan) return; chan=sb.channel('docs-all').on('postgres_changes',{event:'*',schema:'public',table:'docs'},payload=>{
      const row=payload.new&&payload.new.collection?payload.new:payload.old; const c=row&&row.collection; if(!c) return; const set=listeners.get(c); if(set) set.forEach(fn=>fn()); }).subscribe(); }
  function listen(c,fn){ ensureChannel(); if(!listeners.has(c)) listeners.set(c,new Set()); listeners.get(c).add(fn); return ()=>{ const s=listeners.get(c); if(s) s.delete(fn); }; }
  // 폴링 백업(30초): 실시간이 끊겨도 따라옴
  setInterval(()=>{ for(const [,set] of listeners) set.forEach(fn=>fn()); }, 30000);
  const debounce=(fn,ms)=>{ let t; return ()=>{ clearTimeout(t); t=setTimeout(fn,ms); }; };

  function snap(row){ const data=row?Object.freeze({...row.data}):undefined; return {id:row?row.id:'',exists:!!row,data:()=>data,metadata:{fromCache:false,hasPendingWrites:false}}; }
  function checkPath(path,even){ const segs=String(path).split('/').filter(Boolean); if(segs.length===0||segs.length%2!==(even?0:1)) throw new TypeError('bad path parity: '+path); for(const s of segs) if(!/^[A-Za-z0-9_\-.~:@+]{1,200}$/.test(s)) throw new TypeError('bad segment: '+s); return segs; }

  function docRef(path){
    const segs=checkPath(path,true); const id=segs[segs.length-1], collection=segs.slice(0,-1).join('/');
    const ref={id,path,
      async get(){ const {data,error}=await sb.from('docs').select('id,data').eq('collection',collection).eq('id',id).maybeSingle(); if(error) throw mapErr(error); return snap(data); },
      async set(body){ const {error}=await sb.from('docs').upsert({collection,id,data:body},{onConflict:'collection,id'}); if(error) throw mapErr(error); },
      async update(patch){ const {error}=await sb.rpc('doc_update',{p_collection:collection,p_id:id,p_patch:patch}); if(error) throw mapErr(error); },
      async delete(){ const {error}=await sb.from('docs').delete().eq('collection',collection).eq('id',id); if(error) throw mapErr(error); },
      onSnapshot(next,onErr){ let alive=true; const run=debounce(async()=>{ try{ const s=await ref.get(); if(alive) next(s); }catch(e){ if(alive&&onErr) onErr(e); } },80);
        run(); const off=listen(collection,run); return ()=>{ alive=false; off(); }; },
      collection(sub){ return collectionRef(path+'/'+sub); },
      async acquire(){ return {acquired:true}; }
    };
    return ref;
  }
  function collectionRef(path, q){
    const segs=checkPath(path,false); const collection=segs.join('/'); q=q||{where:[],order:null,limit:null};
    const applyQ=rows=>{ let out=rows.map(r=>({id:r.id,...r.data,__raw:r}));
      for(const [f,op,v] of q.where){ out=out.filter(d=>{ const x=d[f]; switch(op){ case '==':return x===v; case '!=':return x!==v; case '<':return x<v; case '<=':return x<=v; case '>':return x>v; case '>=':return x>=v; case 'in':return (v||[]).includes(x); case 'not-in':return !(v||[]).includes(x); case 'array-contains':return Array.isArray(x)&&x.includes(v); default:return true; } }); }
      if(q.order){ const [f,dir]=q.order; out.sort((a,b)=>{ const x=a[f],y=b[f]; if(x===undefined&&y===undefined) return 0; if(x===undefined) return 1; if(y===undefined) return -1; return (x<y?-1:x>y?1:0)*(dir==='desc'?-1:1); }); } else out.sort((a,b)=>a.id<b.id?-1:1);
      if(q.limit) out=out.slice(0,q.limit);
      return out.map(d=>snap(d.__raw)); };
    const fetchAll=async()=>{ const {data,error}=await sb.from('docs').select('id,data').eq('collection',collection).limit(5000); if(error) throw mapErr(error); return data||[]; };
    const ref={path,
      doc(id){ return docRef(path+'/'+(id||newId())); },
      async add(body){ const r=docRef(path+'/'+newId()); await r.set(body); return r; },
      where(f,op,v){ return collectionRef(path,{...q,where:[...q.where,[f,op,v]]}); },
      orderBy(f,dir){ return collectionRef(path,{...q,order:[f,dir||'asc']}); },
      limit(n){ return collectionRef(path,{...q,limit:n}); },
      async get(){ const docs=applyQ(await fetchAll()); return {docs,size:docs.length,empty:!docs.length,docChanges:()=>docs.map((d,i)=>({type:'added',doc:d,oldIndex:-1,newIndex:i})),metadata:{fromCache:false,hasPendingWrites:false}}; },
      onSnapshot(next,onErr){ let alive=true; const run=debounce(async()=>{ try{ const s=await ref.get(); if(alive) next(s); }catch(e){ if(alive&&onErr) onErr(e); } },120);
        run(); const off=listen(collection,run); return ()=>{ alive=false; off(); }; }
    };
    return ref;
  }
  const db={doc:docRef,collection:collectionRef};

  /* ---------- user ---------- */
  let session=null, admin=false, profileCache=new Map();
  const initials=(name,color)=>{ const c=document.createElement('canvas'); c.width=c.height=64; const x=c.getContext('2d'); x.fillStyle=color; x.beginPath(); x.arc(32,32,32,0,7); x.fill(); x.fillStyle='#fff'; x.font='600 28px sans-serif'; x.textAlign='center'; x.textBaseline='middle'; x.fillText((name||'?').trim().slice(0,1),32,34); return c.toDataURL(); };
  const colorOf=s=>{ let h=0; for(const ch of String(s||'')) h=(h*31+ch.charCodeAt(0))%360; return `hsl(${h} 42% 42%)`; };
  async function loadSession(){ const {data}=await sb.auth.getSession(); session=data.session||null; if(session){ const {data:a}=await sb.rpc('is_admin'); admin=!!a; } else admin=false; }
  const user={
    async isOwner(){ return admin; }, async canEdit(){ return admin; },
    async can(name){ if(!session) return false; if(name==='data.write') return true; if(name==='files.write'||name==='assets.write') return admin; return false; },
    async id(){ return session?session.user.id:null; },
    async me(){ const id=session?session.user.id:null; const ps=id?await user.profiles([id]):{}; const p=id?ps[id]:null; return {id,name:p?p.name:'',avatarUrl:p?p.avatarUrl:initials('?','#999'),color:colorOf(id),email:session?session.user.email:null,isOwner:admin,canEdit:admin}; },
    async profiles(ids){ ids=Array.isArray(ids)?ids:[ids]; const need=ids.filter(i=>!profileCache.has(i)); if(need.length){ const {data}=await sb.from('profiles').select('id,display_name,avatar_url').in('id',need); (data||[]).forEach(r=>profileCache.set(r.id,r)); need.forEach(i=>{ if(!profileCache.has(i)) profileCache.set(i,null); }); }
      const out={}; for(const i of ids){ const r=profileCache.get(i); const name=r?r.display_name:''; out[i]={id:i,name,avatarUrl:(r&&r.avatar_url)||initials(name||'?',colorOf(i)),color:colorOf(i),email:null,isMe:session&&session.user.id===i,guest:false}; } return out; },
    async name(){ return (await user.me()).name; }, async avatarUrl(){ return (await user.me()).avatarUrl; }, async search(){ return []; }, async email(){ return session?session.user.email:null; }
  };

  /* ---------- assets (Storage) ---------- */
  const bucket=C.BUCKET||'media';
  const publicUrl=id=>sb.storage.from(bucket).getPublicUrl(id).data.publicUrl;
  const assets={
    async upload(blob,opts){ if(!session) throw err('not_granted'); const type=(opts&&opts.type)||blob.type||'image/jpeg'; const ext=({'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'})[type]||'bin';
      const id=`${session.user.id}/${Date.now().toString(36)}${newId().slice(0,6)}.${ext}`; const {error}=await sb.storage.from(bucket).upload(id,blob,{contentType:type,upsert:false}); if(error) throw err(/exceeded|size/i.test(error.message)?'too_large':'upstream_error',error.message);
      return {id,url:publicUrl(id),sizeBytes:blob.size,contentType:type}; },
    async delete(id){ const {error}=await sb.storage.from(bucket).remove([id]); if(error) throw err('upstream_error',error.message); return {deleted:true}; },
    async list(){ return {assets:[],usage:{files:0,bytes:0,maxFiles:0,maxBytes:0}}; }
  };
  window.blobUrl=id=>publicUrl(id);

  /* ---------- downloads ---------- */
  const downloads={ async save({filename,data}){ const blob=data instanceof Blob?data:new Blob([data]); const u=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=u; a.download=filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(u),4000); return {status:'saved'}; } };

  /* ---------- 앱 전용 RPC ---------- */
  window.dj={
    joinOrg:async code=>{ const {data,error}=await sb.rpc('join_org',{p_code:code}); if(error) throw mapErr(error); return data; },
    collabAnswer:async(pid,orgId,accept)=>{ const {error}=await sb.rpc('collab_answer',{p_post:pid,p_org:orgId,p_accept:accept}); if(error) throw mapErr(error); },
    reportTarget:async(c,id,key)=>{ const {error}=await sb.rpc('report_target',{p_collection:c,p_id:id,p_key:key}); if(error) throw mapErr(error); },
    storySeen:async id=>{ await sb.rpc('story_seen',{p_id:id}); },
    deleteMe:async()=>{ const {error}=await sb.rpc('delete_me'); if(error) throw mapErr(error); await sb.auth.signOut(); },
    signIn:async(email,password)=>{ const {error}=await sb.auth.signInWithPassword({email,password}); if(error) throw error; },
    signUp:async(email,password,displayName,rec)=>{ let release; holdReload=new Promise(r=>release=r);
      try{ const {data,error}=await sb.auth.signUp({email,password,options:{data:{display_name:displayName}}}); if(error) throw error;
        if(data&&data.session&&rec&&rec.q&&rec.a){ try{ await sb.rpc('set_recovery',{p_question:rec.q,p_answer:rec.a}); }catch(_){} }
        return data; } finally { release(); } },
    setRecovery:async(q,a)=>{ const {error}=await sb.rpc('set_recovery',{p_question:q,p_answer:a}); if(error) throw mapErr(error); },
    myRecoveryQuestion:async()=>{ const {data}=await sb.rpc('my_recovery_question'); return data||null; },
    recoveryQuestion:async email=>{ const {data,error}=await sb.rpc('recovery_question',{p_email:email}); if(error) throw mapErr(error); return data; },
    recoveryReset:async(email,answer,pw)=>{ const {data,error}=await sb.rpc('recovery_reset',{p_email:email,p_answer:answer,p_new_password:pw}); if(error) throw mapErr(error); return data; },
    updatePassword:async pw=>{ const {error}=await sb.auth.updateUser({password:pw}); if(error) throw error; try{ await sb.rpc('pw_temp_clear'); }catch(_){} },
    recoveryTemp:async(email,answer)=>{ const {data,error}=await sb.rpc('recovery_temp',{p_email:email,p_answer:answer}); if(error) throw mapErr(error); return data||{status:'wrong'}; },
    changePassword:async(current,pw)=>{ const email=session&&session.user&&session.user.email; if(!email) throw new Error('not signed in');
      const r=await sb.auth.signInWithPassword({email,password:current}); if(r.error) throw new Error('wrong current');
      const {error}=await sb.auth.updateUser({password:pw}); if(error) throw error; try{ await sb.rpc('pw_temp_clear'); }catch(_){} },
    tempPending:async()=>{ const {data}=await sb.rpc('pw_temp_pending'); return !!data; },
    signOut:async()=>{ await sb.auth.signOut(); },
    resetPassword:async email=>{ const {error}=await sb.auth.resetPasswordForEmail(email,{redirectTo:location.origin+location.pathname}); if(error) throw error; },
    myStatus:async()=>{ if(!session) return null; const {data}=await sb.from('account_status').select('status,reason,until').eq('user_id',session.user.id).maybeSingle(); if(!data) return null; if(data.until&&new Date(data.until)<new Date()) return null; return data; },
    listUsers:async()=>{ const {data,error}=await sb.rpc('admin_list_users'); if(error) throw mapErr(error); return data||[]; },
    setStatus:async(uid,status,reason,days,hide)=>{ const {error}=await sb.rpc('admin_set_status',{p_user:uid,p_status:status,p_reason:reason||'',p_days:days||0,p_hide:!!hide}); if(error) throw mapErr(error); },
    session:()=>session, isAdmin:()=>admin
  };
  let holdReload=Promise.resolve();
  const ready=loadSession();
  /* 로그인 상태가 '실제로 바뀔 때만' 새로고침 (세션 복원·토큰 갱신 때 반복 새로고침되던 문제 수정) */
  sb.auth.onAuthStateChange((ev,sess)=>{ if(ev==='INITIAL_SESSION'||ev==='TOKEN_REFRESHED') return;
    if(ev==='PASSWORD_RECOVERY'){ try{ localStorage.setItem('dj_pw_recovery','1'); }catch(_){} }
    Promise.all([ready,holdReload]).then(()=>{ const now=sess&&sess.user?sess.user.id:null, before=session&&session.user?session.user.id:null;
      if(now!==before){ session=sess; setTimeout(()=>location.reload(),60); } }); });

  window.claude={ use:async name=>{ await ready; return ({db,user,assets,downloads})[name]||null; } };
})();
