import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from './CommandPalette'
import { useAuthStore } from '@/stores/authStore'
import { NAV_GROUPS } from './navigation'
export { NAV_GROUPS } from './navigation'



export const Layout=()=>{const location=useLocation();const [sidebarOpen,setSidebarOpen]=useState(true);const [mobileOpen,setMobileOpen]=useState(false);const [commandOpen,setCommandOpen]=useState(false);const {user}=useAuthStore();const filteredGroups=useMemo(()=>{if(!user)return [];return NAV_GROUPS.map(g=>({...g,items:g.items.filter(i=>i.roles.includes('all')||i.roles.includes(user.role))})).filter(g=>g.items.length>0)},[user]);const flat=useMemo(()=>filteredGroups.flatMap(g=>g.items),[filteredGroups]);return <div className="relative min-h-screen overflow-x-clip bg-background"><div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden="true"><div className="absolute start-[18%] top-[-16%] h-[42rem] w-[42rem] rounded-full bg-primary/5 blur-3xl"/><div className="absolute end-[-12%] top-[20%] h-[34rem] w-[34rem] rounded-full bg-violet-500/5 blur-3xl"/><div className="absolute inset-0 opacity-[0.02] [background-image:linear-gradient(to_right,currentColor_1px,transparent_1px),linear-gradient(to_bottom,currentColor_1px,transparent_1px)] [background-size:72px_72px]"/></div>{mobileOpen&&<button aria-label="Close navigation" className="fixed inset-0 z-40 bg-slate-950/50 backdrop-blur-sm lg:hidden" onClick={()=>setMobileOpen(false)}/>}<Sidebar open={sidebarOpen} onOpenChange={setSidebarOpen} mobileOpen={mobileOpen} onMobileOpenChange={setMobileOpen} groups={filteredGroups} flatNavigation={flat} currentPath={location.pathname}/><div className={`relative min-h-screen min-w-0 transition-[margin] duration-300 ${sidebarOpen?'lg:ms-64':'lg:ms-[76px]'}`}><Header sidebarOpen={sidebarOpen} onSidebarToggle={()=>setSidebarOpen(v=>!v)} onMobileToggle={()=>setMobileOpen(true)} onCommandOpen={()=>setCommandOpen(true)}/><main className="flex-1 overflow-auto px-4 py-5 lg:px-7 lg:py-7"><div className="mx-auto w-full max-w-[1680px]"><motion.div key={location.pathname} initial={{opacity:0,y:12,scale:.995}} animate={{opacity:1,y:0,scale:1}} transition={{duration:.28,ease:[.22,1,.36,1]}}><Outlet/></motion.div></div></main></div><CommandPalette open={commandOpen} onOpenChange={setCommandOpen}/></div>}
