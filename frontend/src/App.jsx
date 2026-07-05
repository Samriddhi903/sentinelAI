import { useEffect } from 'react'
import { ThemeProvider } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import { BrowserRouter } from 'react-router-dom'

import AppRoutes from './routes/Routes'
import AppShell from './layouts/AppShell'
import { theme } from './theme/theme'

export default function App() {
  useEffect(() => {
    document.title = 'SentinelAI'
  }, [])

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <AppShell>
          <AppRoutes />
        </AppShell>
      </BrowserRouter>
    </ThemeProvider>
  )
}

