import { createTheme } from '@mui/material/styles'

const palette = {
  mode: 'dark',
  background: {
    default: '#0F172A',
    paper: '#1E293B',
  },
  primary: {
    main: '#3B82F6',
  },
  success: {
    main: '#10B981',
  },
  warning: {
    main: '#F59E0B',
  },
  error: {
    main: '#EF4444',
  },
  text: {
    primary: '#F8FAFC',
    secondary: '#94A3B8',
  },
}

export const theme = createTheme({
  palette,
  typography: {
    fontFamily: 'Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
    h4: { fontWeight: 650, letterSpacing: '-0.02em' },
    h6: { fontWeight: 600 },
    body2: { color: palette.text.secondary },
  },
  shape: { borderRadius: 12 },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        'html, body': {
          height: '100%',
        },
        body: {
          backgroundColor: palette.background.default,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: palette.background.paper,
          border: '1px solid rgba(148, 163, 184, 0.18)',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: palette.background.paper,
          border: '1px solid rgba(148, 163, 184, 0.18)',
        },
      },
    },
    MuiButton: {
      defaultProps: {
        disableElevation: true,
      },
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 10,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { borderRadius: 10 },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          color: palette.text.secondary,
          fontWeight: 650,
          borderBottom: '1px solid rgba(148, 163, 184, 0.18)',
        },
        body: {
          color: palette.text.primary,
          borderBottom: '1px solid rgba(148, 163, 184, 0.12)',
        },
      },
    },
  },
})

