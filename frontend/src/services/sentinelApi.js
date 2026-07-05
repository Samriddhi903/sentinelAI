import { api } from './apiClient'

export const sentinelApi = {
  uploadLog: async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    // backend expects multipart field name: file
    const res = await api.post('/api/v1/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return res.data
  },

  getUploadStatus: async (uploadId) => {
    const res = await api.get(`/api/v1/upload/${encodeURIComponent(uploadId)}/status`)
    return res.data
  },

  processUpload: async (uploadId) => {
    const res = await api.post(`/api/v1/upload/${encodeURIComponent(uploadId)}/process`)
    return res.data
  },

  normalizeUpload: async (uploadId) => {
    const res = await api.post(`/api/v1/upload/${encodeURIComponent(uploadId)}/normalize`)
    return res.data
  },

  extractFeatures: async (uploadId) => {
    const res = await api.post(`/api/v1/upload/${encodeURIComponent(uploadId)}/features`)
    return res.data
  },


  startAnalysis: async (uploadId) => {
    const res = await api.post(`/api/v1/upload/${encodeURIComponent(uploadId)}/analyze`)
    return res.data
  },

  getAnalysis: async (uploadId) => {
    const res = await api.get(`/api/v1/upload/${encodeURIComponent(uploadId)}/analysis`)
    return res.data
  },




  generateReport: async (uploadId) => {
    const res = await api.post(`/api/v1/upload/${encodeURIComponent(uploadId)}/report`)

    return res.data
  },

  getReport: async (uploadId) => {
    const res = await api.get(`/api/v1/upload/${encodeURIComponent(uploadId)}/report`)
    return res.data
  },
}

