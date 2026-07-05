import { useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Button from '@mui/material/Button'
import Alert from '@mui/material/Alert'
import LinearProgress from '@mui/material/LinearProgress'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Chip from '@mui/material/Chip'
import UploadFileIcon from '@mui/icons-material/UploadFile'
import DescriptionIcon from '@mui/icons-material/Description'

import { sentinelApi } from '../services/sentinelApi'
import { useNavigate } from 'react-router-dom'

const allowedExtensions = new Set(['.apache', '.log', '.txt', '.json', '.syslog', '.nginx'])

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = bytes
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export default function UploadPage() {
  const navigate = useNavigate()

  const [dragActive, setDragActive] = useState(false)
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [analysisRunning, setAnalysisRunning] = useState(false)
  const [statusMsg, setStatusMsg] = useState('')
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(0)

  const [extractingFeatures, setExtractingFeatures] = useState(false)
  const [runningAnalysis, setRunningAnalysis] = useState(false)
  const [generatingInvestigation, setGeneratingInvestigation] = useState(false)


  const hints = useMemo(
    () => [
      { label: 'Supported', value: 'Apache, Nginx, Syslog, JSON' },
      { label: 'Flow', value: 'Upload → Feature Extraction → Analyze' },
    ],
    [],
  )


  const reset = () => {
    setDragActive(false)
    setFile(null)
    setUploading(false)
    setAnalysisRunning(false)
    setExtractingFeatures(false)
    setRunningAnalysis(false)
    setGeneratingInvestigation(false)
    setStatusMsg('')
    setError(null)
    setProgress(0)
  }


  const onFileSelected = async (f) => {
    if (!f) return
    setError(null)
    setStatusMsg('')
    setProgress(0)
    setFile(f)
  }

  const startWorkflow = async () => {
    if (!file) return
    const uploadFile = file

    try {
      setError(null)

      setUploading(true)
      setExtractingFeatures(false)
      setRunningAnalysis(false)
      setGeneratingInvestigation(false)
      setAnalysisRunning(true)


      setStatusMsg('Uploading Log…')
      setProgress(10)

      const uploadRes = await sentinelApi.uploadLog(uploadFile)
      const uploadId = uploadRes?.upload_id
      if (!uploadId) throw new Error('Upload succeeded but no upload_id was returned.')

      setStatusMsg('Normalizing Events…')
      setProgress(25)

      await sentinelApi.processUpload(uploadId)
      await sentinelApi.normalizeUpload(uploadId)

      setStatusMsg('Extracting Features…')

      setProgress(45)
      setExtractingFeatures(true)

      await sentinelApi.extractFeatures(uploadId)

      setExtractingFeatures(false)

      setRunningAnalysis(true)
      setStatusMsg('Running Analysis…')
      setProgress(70)

      await sentinelApi.startAnalysis(uploadId)

      setRunningAnalysis(false)
      setGeneratingInvestigation(true)
      setStatusMsg('Generating Investigation…')
      setProgress(85)

      // Backend may take additional time; poll analysis endpoint.

      const startedAt = Date.now()
      const timeoutMs = 1000 * 60

      while (Date.now() - startedAt < timeoutMs) {
        try {
          const analysis = await sentinelApi.getAnalysis(uploadId)
          if (analysis?.investigation?.investigation_id) {
            setProgress(100)
            setUploading(false)
            setAnalysisRunning(false)
            setGeneratingInvestigation(false)
            navigate(`/analysis/${uploadId}`)
            return
          }
        } catch {
          // analysis not ready yet; ignore and keep polling
        }

        setProgress((p) => Math.min(95, p + 5))
        await new Promise((r) => setTimeout(r, 1500))
      }

      throw new Error('Investigation generation timed out. Please try again.')
    } catch (e) {
      // Prefer backend error detail when available.
      setError(e?.response?.data?.detail || e?.response?.data?.message || e.message || 'Upload flow failed')
      setUploading(false)
      setAnalysisRunning(false)
      setExtractingFeatures(false)
      setRunningAnalysis(false)
      setGeneratingInvestigation(false)
      setProgress(0)
    }
  }


  return (
    <Box>
      <Stack spacing={2} sx={{ mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 800 }}>
          Upload Logs
        </Typography>
        <Typography variant="body1" sx={{ color: 'text.secondary' }}>
          Create a new investigation by uploading your log file. The system will run detection,
          analysis, and generate an investigation chain.
        </Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1}>
          {hints.map((h) => (
            <Chip key={h.label} label={`${h.label}: ${h.value}`} sx={{ alignSelf: 'flex-start' }} />
          ))}
        </Stack>
      </Stack>

      <Paper
        variant="outlined"
        sx={{
          p: { xs: 2, md: 3 },
          borderStyle: 'dashed',
          borderColor: dragActive ? 'primary.main' : 'rgba(148,163,184,0.25)',
          backgroundColor: dragActive ? 'rgba(59,130,246,0.08)' : 'transparent',
        }}
        onDragEnter={(e) => {
          e.preventDefault()
          setDragActive(true)
        }}
        onDragOver={(e) => {
          e.preventDefault()
          setDragActive(true)
        }}
        onDragLeave={(e) => {
          e.preventDefault()
          setDragActive(false)
        }}
        onDrop={(e) => {
          e.preventDefault()
          setDragActive(false)
          const f = e.dataTransfer.files?.[0]
          onFileSelected(f)
        }}
      >
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              border: '1px solid rgba(148,163,184,0.25)',
              backgroundColor: 'rgba(30,41,59,0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <UploadFileIcon color="primary" />
          </Box>

          <Box sx={{ flex: 1 }}>
            <Typography sx={{ fontWeight: 750 }}>
              Drag & drop your log file here
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
              Supported: Apache, Nginx, Syslog, JSON. File is uploaded securely to start the investigation.
            </Typography>
          </Box>

          <Button
            variant="contained"
            component="label"
            disabled={uploading || analysisRunning}
            sx={{ px: 3 }}
          >
            Choose file
            <input
              hidden
              type="file"
              onChange={(e) => onFileSelected(e.target.files?.[0] || null)}
            />
          </Button>
        </Stack>

        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mt: 2 }}>
          <Paper
            variant="outlined"
            sx={{
              flex: 1,
              p: 1.5,
              bgcolor: 'rgba(30,41,59,0.35)',
              borderColor: 'rgba(148,163,184,0.22)',
            }}
          >
            {file ? (
              <Stack direction="row" spacing={1.5} alignItems="center">
                <DescriptionIcon color="primary" fontSize="small" />
                <Box>
                  <Typography sx={{ fontWeight: 700 }}>{file.name}</Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    {formatBytes(file.size)} · ready to analyze
                  </Typography>
                </Box>
              </Stack>
            ) : (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                No file selected.
              </Typography>
            )}
          </Paper>

          <Stack direction="row" spacing={1}>
            <Button
              variant="outlined"
              color="inherit"
              disabled={uploading || analysisRunning || !file}
              onClick={reset}
            >
              Reset
            </Button>
            <Button
              variant="contained"
              disabled={uploading || analysisRunning || !file}
              onClick={startWorkflow}
              sx={{ px: 3 }}
            >
              Upload & Analyze
            </Button>
          </Stack>
        </Stack>
      </Paper>

      {uploading || analysisRunning || extractingFeatures || runningAnalysis || generatingInvestigation ? (
        <Paper variant="outlined" sx={{ mt: 3, p: 2 }}>
          <Stack spacing={1}>
            <Typography sx={{ fontWeight: 700 }}>
              {statusMsg || 'Working…'}
            </Typography>
            <LinearProgress variant="determinate" value={progress} />
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Tip: Don’t refresh—results will load automatically.
            </Typography>
          </Stack>
        </Paper>
      ) : null}


      {error ? (
        <Alert severity="error" sx={{ mt: 3 }}>
          {error}
        </Alert>
      ) : null}

      <Box sx={{ mt: 3, color: 'text.secondary', fontSize: 13 }}>
        By continuing, you confirm the log file is safe to process in your environment.
      </Box>
    </Box>
  )
}

