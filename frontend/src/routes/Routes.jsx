import { Navigate, Route, Routes } from 'react-router-dom'

import UploadPage from '../pages/UploadPage'
import AnalysisPage from '../pages/AnalysisPage'
import InvestigationPage from '../pages/InvestigationPage'
import TimelinePage from '../pages/TimelinePage'
import MitrePage from '../pages/MitrePage'
import AIReportPage from '../pages/AIReportPage'
import NotFoundPage from '../pages/NotFoundPage'

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/upload" replace />} />

      <Route path="/upload" element={<UploadPage />} />
      <Route path="/analysis/:uploadId" element={<AnalysisPage />} />
      <Route path="/investigation/:uploadId" element={<InvestigationPage />} />
      <Route path="/timeline/:uploadId" element={<TimelinePage />} />
      <Route path="/mitre/:uploadId" element={<MitrePage />} />
      <Route path="/ai-report/:uploadId" element={<AIReportPage />} />

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

