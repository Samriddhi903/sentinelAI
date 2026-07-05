import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import CircularProgress from '@mui/material/CircularProgress'
import Chip from '@mui/material/Chip'

import { sentinelApi } from '../services/sentinelApi'
import { useParams } from 'react-router-dom'

export default function MitrePage() {
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
        setError(e?.response?.data?.detail || e.message || 'Failed to load MITRE techniques')
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

  const techniques = analysis?.investigation?.mitre_techniques || []

  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 900, mb: 2 }}>MITRE ATT&CK View</Typography>

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
          <Stack spacing={1.2}>
            <Typography sx={{ fontWeight: 850 }}>Detected Techniques</Typography>
            {techniques.length ? (
              <Stack direction="row" sx={{ flexWrap: 'wrap' }} gap={1.2}>

                {techniques.map((t) => (
                  <Chip
                    key={t}
                    label={t}
                    variant="outlined"
                    sx={{ px: 1.5, py: 1 }}
                  />
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>No MITRE techniques returned.</Typography>
            )}
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Techniques are mapped from analysis detections.
            </Typography>
          </Stack>
        </Paper>
      ) : null}
    </Box>
  )
}

