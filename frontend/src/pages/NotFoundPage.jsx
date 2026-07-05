import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Button from '@mui/material/Button'
import { useNavigate } from 'react-router-dom'

export default function NotFoundPage() {
  const navigate = useNavigate()
  return (
    <Box>
      <Paper variant="outlined" sx={{ p: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 900, mb: 1 }}>Page not found</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          The requested view doesn’t exist.
        </Typography>
        <Button variant="contained" onClick={() => navigate('/upload')}>Go to Upload</Button>
      </Paper>
    </Box>
  )
}

