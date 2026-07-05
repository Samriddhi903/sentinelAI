import { useMemo, useState } from 'react'
import { Link as RouterLink, useLocation } from 'react-router-dom'
import Box from '@mui/material/Box'
import Drawer from '@mui/material/Drawer'
import IconButton from '@mui/material/IconButton'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import useMediaQuery from '@mui/material/useMediaQuery'
import Divider from '@mui/material/Divider'
import MenuIcon from '@mui/icons-material/Menu'
import SecurityIcon from '@mui/icons-material/Security'

const drawerWidth = 264

export default function AppShell({ children }) {
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const isDesktop = useMediaQuery('(min-width: 900px)')

  const items = useMemo(
    () => [
      { label: 'Upload Logs', to: '/upload', icon: <SecurityIcon fontSize="small" /> },
    ],
    [],
  )

  const content = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Toolbar>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box
            sx={{
              width: 34,
              height: 34,
              borderRadius: 2,
              bgcolor: 'rgba(59,130,246,0.18)',
              border: '1px solid rgba(59,130,246,0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <SecurityIcon sx={{ color: 'primary.main' }} fontSize="small" />
          </Box>
          <Box>
            <Typography sx={{ fontWeight: 750, lineHeight: 1.1 }}>SentinelAI</Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Investigation Console
            </Typography>
          </Box>
        </Box>
      </Toolbar>
      <Divider />
      <List sx={{ px: 1 }}>
        {items.map((it) => {
          const selected = location.pathname === it.to || location.pathname.startsWith(it.to + '/')
          return (
            <ListItem key={it.to} disablePadding>
              <ListItemButton
                component={RouterLink}
                to={it.to}
                selected={selected}
                onClick={() => setMobileOpen(false)}
                sx={{
                  borderRadius: 2,
                  '&.Mui-selected': {
                    bgcolor: 'rgba(59,130,246,0.16)',
                    border: '1px solid rgba(59,130,246,0.35)',
                  },
                }}
              >
                <Box sx={{ mr: 1.25, color: selected ? 'primary.main' : 'text.secondary' }}>{it.icon}</Box>
                <ListItemText primary={it.label} />
              </ListItemButton>
            </ListItem>
          )
        })}
      </List>
      <Box sx={{ flexGrow: 1 }} />
      <Box sx={{ p: 2 }}>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Enterprise-ready UX. API-driven.
        </Typography>
      </Box>
    </Box>
  )

  return (
    <Box sx={{ display: 'flex', minHeight: '100svh' }}>
      <Drawer
        variant={isDesktop ? 'permanent' : 'temporary'}
        open={isDesktop ? true : mobileOpen}
        onClose={() => setMobileOpen(false)}
        ModalProps={{ keepMounted: true }}
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': { width: drawerWidth, bgcolor: '#0F172A' },
        }}
      >
        {content}
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1 }}>
        <Toolbar />
        <Box sx={{ px: { xs: 2, md: 3 }, pb: 4 }}>{children}</Box>
      </Box>

      {!isDesktop && (
        <IconButton
          onClick={() => setMobileOpen(true)}
          sx={{ position: 'fixed', top: 18, left: 14, bgcolor: 'rgba(30,41,59,0.9)', border: '1px solid rgba(148,163,184,0.18)' }}
        >
          <MenuIcon />
        </IconButton>
      )}
    </Box>
  )
}

