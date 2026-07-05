import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import CircularProgress from '@mui/material/CircularProgress'
import Chip from '@mui/material/Chip'

import { sentinelApi } from '../services/sentinelApi'
import { useParams } from 'react-router-dom'

export default function TimelinePage() {
  const { uploadId } = useParams()

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [analysis, setAnalysis] = useState(null)

  useEffect(() => {
    let alive = true
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const res = await sentinelApi.getAnalysis(uploadId)
        if (!alive) return
        setAnalysis(res)
      } catch (e) {
        if (!alive) return
        setError(e?.response?.data?.detail || e.message || 'Failed to load timeline')
      } finally {
        if (!alive) return
        setLoading(false)
      }
    }
    load()
    return () => {
      alive = false
    }
  }, [uploadId])

  const chain = analysis?.timeline?.attack_chain || []

  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 900, mb: 2 }}>Attack Timeline</Typography>

      {loading ? (
        <Paper variant="outlined" sx={{ p: 3, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Paper>
      ) : error ? (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography color="error" sx={{ fontWeight: 800 }}>{error}</Typography>
        </Paper>
      ) : null}

      {!loading && analysis ? (
        <Paper sx={{ p: 2.2 }}>
          <Stack spacing={1.5}>
            <Typography sx={{ fontWeight: 850 }}>Attack Chain</Typography>
            {chain.length ? (
              <Box
                sx={{
                  display: 'grid',
                  gridTemplateColumns: { xs: '1fr', md: 'repeat(6, 1fr)' },
                  gap: 1.3,
                }}
              >
                {chain.map((step, idx) => (
                  <Box
                    key={`${step}-${idx}`}
                    sx={{
                      p: 1.2,
                      borderRadius: 2,
                      border: '1px solid rgba(148,163,184,0.18)',
                      bgcolor: 'rgba(30,41,59,0.25)',
                    }}
                  >
                    <Typography variant="body2" sx={{ color: 'text.secondary', mb: 0.6 }}>
                      Stage {idx + 1}
                    </Typography>
                    <Typography sx={{ fontWeight: 850 }}>{step}</Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      From detection context
                    </Typography>
                    {idx !== chain.length - 1 && (
                      <Box sx={{ mt: 1.1, display: { xs: 'none', md: 'block' }, textAlign: 'center', opacity: 0.55 }}>
                        <Typography sx={{ fontWeight: 900 }}>↓</Typography>
                      </Box>
                    )}
                  </Box>
                ))}
              </Box>
            ) : (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>No timeline data returned.</Typography>
            )}

            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Timeline is derived from normalized investigation flow.
            </Typography>
          </Stack>
        </Paper>
      ) : null}
    </Box>
  )
}

