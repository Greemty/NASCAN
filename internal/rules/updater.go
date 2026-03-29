package rules

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

const releasesAPI = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"

type Bundle string

const (
	BundleCore     Bundle = "core"
	BundleExtended Bundle = "extended"
	BundleFull     Bundle = "full"
)

func (b Bundle) assetName() string {
	return "yara-forge-rules-" + string(b) + ".zip"
}

func (b Bundle) yarName() string {
    return "yara-rules-" + string(b) + ".yar"
}

type Updater struct {
	rulesDir string
	bundle   Bundle
	logger   *zap.Logger
	client   *http.Client
}

func NewUpdater(rulesDir, bundle string, logger *zap.Logger) *Updater {
	b := Bundle(bundle)
	switch b {
	case BundleCore, BundleExtended, BundleFull:
	default:
		logger.Warn("unknown bundle, falling back to core", zap.String("bundle", bundle))
		b = BundleCore
	}
	return &Updater{
		rulesDir: rulesDir,
		bundle:   b,
		logger:   logger,
		client:   &http.Client{Timeout: 120 * time.Second},
	}
}

func (u *Updater) RulesPath() string {
	return filepath.Join(u.rulesDir, u.bundle.yarName())
}

func (u *Updater) EnsureRules(ctx context.Context, forceUpdate bool) error {
	if !forceUpdate {
		if _, err := os.Stat(u.RulesPath()); err == nil {
			u.logger.Info("rules already present", zap.String("path", u.RulesPath()))
			return nil
		}
	}

	downloadURL, tag, err := u.resolveLatestAsset(ctx)
	if err != nil {
		return fmt.Errorf("resolving YARA-Forge release: %w", err)
	}

	u.logger.Info("downloading rules",
		zap.String("release", tag),
		zap.String("asset", u.bundle.assetName()),
	)

	if err := os.MkdirAll(u.rulesDir, 0o755); err != nil {
		return fmt.Errorf("creating rules dir: %w", err)
	}

	zipPath := filepath.Join(u.rulesDir, u.bundle.assetName())
	if err := u.downloadAtomic(ctx, downloadURL, zipPath); err != nil {
		return fmt.Errorf("downloading ZIP: %w", err)
	}
	defer os.Remove(zipPath)  // ← déplace cette ligne ICI, après le download

	if err := u.extractYar(zipPath); err != nil {
		return fmt.Errorf("extracting rules: %w", err)
	}

	u.logger.Info("rules ready", zap.String("path", u.RulesPath()))
	return nil
}

func (u *Updater) resolveLatestAsset(ctx context.Context) (downloadURL, tag string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPI, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := u.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("decoding release JSON: %w", err)
	}

	for _, asset := range release.Assets {
		if asset.Name == u.bundle.assetName() {
			return asset.BrowserDownloadURL, release.TagName, nil
		}
	}

	return "", "", fmt.Errorf("asset %q not found in release %s", u.bundle.assetName(), release.TagName)
}

func (u *Updater) downloadAtomic(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	return os.Rename(tmp, dest)
}

func (u *Updater) extractYar(zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	target := u.bundle.yarName()

	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, target) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		dest := u.RulesPath()
		tmp := dest + ".tmp"
		out, err := os.Create(tmp)
		if err != nil {
			rc.Close()
			return err
		}

		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			os.Remove(tmp)
			return err
		}
		out.Close()
		rc.Close()

		return os.Rename(tmp, dest)
	}

	return fmt.Errorf("file %q not found inside ZIP", target)
}