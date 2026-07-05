import { useEffect, useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import CircularProgress from '@mui/material/CircularProgress'
import Button from '@mui/material/Button'

import { sentinelApi } from '../services/sentinelApi'

import { useNavigate, useParams } from 'react-router-dom'

import Card from '@mui/material/Card'
import Grid from '@mui/material/Grid'
import Divider from '@mui/material/Divider'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'

function severityColor(sev) {
  const s = String(sev || '').toLowerCase()
  if (s.includes('critical')) return 'error'
  if (s.includes('high')) return 'warning'
  if (s.includes('medium')) return 'primary'
  return 'default'
}

export default function AnalysisPage() {
  const { uploadId } = useParams()
  const navigate = useNavigate()

  const [loading, setLoading] = useState(true)
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState(null)

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
        setError(e?.response?.data?.detail || e.message || 'Failed to fetch analysis')
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

  const severity = analysis?.risk_assessment?.severity || analysis?.severity
  const riskScore = analysis?.risk_assessment?.risk_score ?? analysis?.risk_assessment?.riskScore ?? null

  const riskScoreNumber = typeof riskScore === 'number' ? riskScore : Number(riskScore)
  const riskColor = (() => {
    if (!Number.isFinite(riskScoreNumber)) return 'default'
    if (riskScoreNumber <= 30) return 'success'
    if (riskScoreNumber <= 60) return 'warning'
    if (riskScoreNumber <= 80) return 'warning'
    return 'error'
  })()

  const anomalyDetection = analysis?.anomaly_detection
  const anomalyScore = anomalyDetection?.anomaly_score ?? null
  const isAnomalous = anomalyDetection?.is_anomalous ?? null

  const anomalyColor = (() => {
    const s = anomalyScore
    const n = typeof s === 'number' ? s : Number(s)
    if (!Number.isFinite(n)) return 'default'
    if (n <= 30) return 'success'
    if (n <= 60) return 'warning'
    if (n <= 80) return 'warning'
    return 'error'
  })()

  const anomalyLabel = (() => {
    if (!Number.isFinite(Number(anomalyScore))) return '—'
    if (isAnomalous === true) return 'Anomalous'
    return 'Not Anomalous'
  })()


  const detectedAttacks = useMemo(() => {
    const detections = analysis?.detections || []
    const byType = new Map()
    for (const d of detections) {
      const key = d.detection_type || d.detectionType || d.type || 'Unknown'
      byType.set(key, (byType.get(key) || 0) + 1)
    }
    return Array.from(byType.entries()).map(([type, count]) => ({ type, count }))
  }, [analysis])


  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 850 }}>
            Analysis Results
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Investigation ID and detections for upload <strong>{uploadId}</strong>
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Chip label="Detections" color="primary" variant="outlined" />
          <Chip label="Investigation" variant="outlined" onClick={() => navigate(`/investigation/${uploadId}`)} sx={{ cursor: 'pointer' }} />
        </Stack>
      </Stack>

      {loading ? (
        <Paper variant="outlined" sx={{ p: 3, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Paper>
      ) : error ? (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography color="error" sx={{ fontWeight: 700 }}>
            {error}
          </Typography>
        </Paper>
      ) : null}

      {!loading && analysis ? (
        <Stack spacing={2.5}>
          <Paper sx={{ p: 2.2 }}>
            <Stack spacing={1.5}>
              <Typography sx={{ fontWeight: 800, fontSize: 16 }}>Investigation Summary</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Paper variant="outlined" sx={{ p: 1.7, bgcolor: 'rgba(30,41,59,0.25)' }}>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      Risk Score
                    </Typography>
                    <Typography sx={{ fontSize: 28, fontWeight: 900, lineHeight: 1.1 }}>
                      {riskScore ?? '—'}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper variant="outlined" sx={{ p: 1.7, bgcolor: 'rgba(30,41,59,0.25)' }}>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      Severity
                    </Typography>
                    <Chip
                      label={severity || '—'}
                      color={severityColor(severity)}
                      variant="outlined"
                      sx={{ mt: 1 }}
                    />
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper variant="outlined" sx={{ p: 1.7, bgcolor: 'rgba(30,41,59,0.25)' }}>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      Detected Items
                    </Typography>
                    <Typography sx={{ fontSize: 22, fontWeight: 850 }}>
                      {analysis?.risk_assessment?.detection_count ?? analysis?.detection_count ?? analysis?.detections?.length ?? 0}
                    </Typography>
                  </Paper>
                </Grid>

                <Grid item xs={12} md={4}>
                  <Paper variant="outlined" sx={{ p: 1.7, bgcolor: 'rgba(30,41,59,0.25)' }}>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      Anomaly Score
                    </Typography>
                    <Typography sx={{ fontSize: 28, fontWeight: 900, lineHeight: 1.1 }}>
                      {anomalyScore ?? '—'}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper variant="outlined" sx={{ p: 1.7, bgcolor: 'rgba(30,41,59,0.25)' }}>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      Anomaly Verdict
                    </Typography>
                    <Stack direction="column" spacing={0.5} sx={{ mt: 1 }}>
                      <Chip
                        label={anomalyLabel}
                        color={anomalyColor}
                        variant="outlined"
                      />
                      <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: 13 }}>
                        Score: {anomalyScore ?? '—'}
                      </Typography>
                    </Stack>
                  </Paper>
                </Grid>
              </Grid>


              <Divider sx={{ my: 1.2 }} />
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems={{ xs: 'flex-start', md: 'center' }} justifyContent="space-between">
                <Box>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Source IP
                  </Typography>
                  <Typography sx={{ fontWeight: 800 }}>
                    {analysis?.investigation?.source_ip || '—'}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1}>
                  <Chip
                    label={analysis?.investigation?.incident_type ? `Incident: ${analysis.investigation.incident_type}` : 'Incident'}
                    variant="outlined"
                  />
                  <Chip label="MITRE: Ready" variant="outlined" />
                </Stack>
              </Stack>
            </Stack>
          </Paper>

          <Paper sx={{ p: 2.2 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} alignItems={{ xs: 'flex-start', md: 'center' }} justifyContent="space-between">
              <Typography sx={{ fontWeight: 850, fontSize: 16 }}>Detected Attacks</Typography>
              <Stack direction="row" spacing={1}>
                <Chip label="View timeline" clickable={false} />
                <Button size="small" variant="outlined" onClick={() => navigate(`/timeline/${uploadId}`)}>
                  Timeline
                </Button>
              </Stack>
            </Stack>
            <Box sx={{ mt: 2 }}>
              {detectedAttacks.length ? (
                <Grid container spacing={1.5}>
                  {detectedAttacks.map((a) => (
                    <Grid item xs={12} md={6} key={a.type}>
                      <Card variant="outlined" sx={{ p: 1.6, bgcolor: 'rgba(30,41,59,0.25)', borderColor: 'rgba(148,163,184,0.22)' }}>
                        <Typography sx={{ fontWeight: 800 }}>{a.type}</Typography>
                        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                          Occurrences: {a.count}
                        </Typography>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              ) : (
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  No detections returned.
                </Typography>
              )}
            </Box>
          </Paper>

          <Paper sx={{ p: 2.2 }}>
            <Typography sx={{ fontWeight: 850, fontSize: 16, mb: 1.2 }}>Detection Details</Typography>
            <TableContainer component={Paper} variant="outlined" sx={{ bgcolor: 'transparent', border: 'none' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Detection</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Source IP</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(analysis.detections || []).map((d) => (
                    <TableRow key={d.detection_id || `${d.detection_type}-${d.generated_at}`}
                      hover
                    >
                      <TableCell sx={{ fontWeight: 750 }}>{d.detection_type || d.detectionType || 'Unknown'}</TableCell>
                      <TableCell>{String(d.severity || '')}</TableCell>
                      <TableCell>{typeof d.confidence === 'number' ? `${Math.round(d.confidence * 100)}%` : '—'}</TableCell>
                      <TableCell>{analysis?.investigation?.source_ip || d.source_ip || '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Stack>
      ) : null}
    </Box>
  )
}

